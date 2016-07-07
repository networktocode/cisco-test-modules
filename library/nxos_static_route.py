#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
DOCUMENTATION = '''
---
module: nxos_static_route
version_added: "2.2"
short_description: Manages static route configuration
description:
    - Manages static route configuration
author: Gabriele Gerbino (@GGabriele)
notes:
    - If no vrf is supplied, vrf is set to default
    - If state=absent, the route will be removed, regardless of the non-required parameters.
options:
    prefix:
        description:
            - Destination prefix of static route
        required: true
    next_hop:
        description:
            - Next hop address or interface of static route.
              If interface, it must be the fully-qualified interface name.
        required: true
    vrf:
        description:
            - VRF for static route
        required: false
        default: default
    tag:
        description:
            - Route tag value (numeric).
        required: false
        default: null
    route_name:
        description:
            - Name of the route. Used with the name parameter on the CLI.
        required: false
        default: null
    pref:
        description:
            - Preference or administrative difference of route (range 1-255)
        required: false
        default: null
    state:
        description:
            - Manage the state of the resource
        required: true
        choices: ['present','absent']
    m_facts:
        description:
            - Used to print module facts
        required: false
        default: false
        choices: ['true','false']
'''

# COMMON CODE FOR MIGRATION

import re
import time
import collections
import itertools
import shlex
import itertools

from ansible.module_utils.basic import BOOLEANS_TRUE, BOOLEANS_FALSE

DEFAULT_COMMENT_TOKENS = ['#', '!']

class ConfigLine(object):

    def __init__(self, text):
        self.text = text
        self.children = list()
        self.parents = list()
        self.raw = None

    @property
    def line(self):
        line = ['set']
        line.extend([p.text for p in self.parents])
        line.append(self.text)
        return ' '.join(line)

    def __str__(self):
        return self.raw

    def __eq__(self, other):
        if self.text == other.text:
            return self.parents == other.parents

    def __ne__(self, other):
        return not self.__eq__(other)

def ignore_line(text, tokens=None):
    for item in (tokens or DEFAULT_COMMENT_TOKENS):
        if text.startswith(item):
            return True

def get_next(iterable):
    item, next_item = itertools.tee(iterable, 2)
    next_item = itertools.islice(next_item, 1, None)
    return itertools.izip_longest(item, next_item)

def parse(lines, indent, comment_tokens=None):
    toplevel = re.compile(r'\S')
    childline = re.compile(r'^\s*(.+)$')

    ancestors = list()
    config = list()

    for line in str(lines).split('\n'):
        text = str(re.sub(r'([{};])', '', line)).strip()

        cfg = ConfigLine(text)
        cfg.raw = line

        if not text or ignore_line(text, comment_tokens):
            continue

        # handle top level commands
        if toplevel.match(line):
            ancestors = [cfg]

        # handle sub level commands
        else:
            match = childline.match(line)
            line_indent = match.start(1)
            level = int(line_indent / indent)
            parent_level = level - 1

            cfg.parents = ancestors[:level]

            if level > len(ancestors):
                config.append(cfg)
                continue

            for i in range(level, len(ancestors)):
                ancestors.pop()

            ancestors.append(cfg)
            ancestors[parent_level].children.append(cfg)

        config.append(cfg)

    return config


class CustomNetworkConfig(object):

    def __init__(self, indent=None, contents=None, device_os=None):
        self.indent = indent or 1
        self._config = list()
        self._device_os = device_os

        if contents:
            self.load(contents)

    @property
    def items(self):
        return self._config

    @property
    def lines(self):
        lines = list()
        for item, next_item in get_next(self.items):
            if next_item is None:
                lines.append(item.line)
            elif not next_item.line.startswith(item.line):
                lines.append(item.line)
        return lines

    def __str__(self):
        text = ''
        for item in self.items:
            if not item.parents:
                expand = self.get_section(item.text)
                text += '%s\n' % self.get_section(item.text)
        return str(text).strip()

    def load(self, contents):
        self._config = parse(contents, indent=self.indent)

    def load_from_file(self, filename):
        self.load(open(filename).read())

    def get(self, path):
        if isinstance(path, basestring):
            path = [path]
        for item in self._config:
            if item.text == path[-1]:
                parents = [p.text for p in item.parents]
                if parents == path[:-1]:
                    return item

    def search(self, regexp, path=None):
        regex = re.compile(r'^%s' % regexp, re.M)

        if path:
            parent = self.get(path)
            if not parent or not parent.children:
                return
            children = [c.text for c in parent.children]
            data = '\n'.join(children)
        else:
            data = str(self)

        match = regex.search(data)
        if match:
            if match.groups():
                values = match.groupdict().values()
                groups = list(set(match.groups()).difference(values))
                return (groups, match.groupdict())
            else:
                return match.group()

    def findall(self, regexp):
        regexp = r'%s' % regexp
        return re.findall(regexp, str(self))

    def expand(self, obj, items):
        block = [item.raw for item in obj.parents]
        block.append(obj.raw)

        current_level = items
        for b in block:
            if b not in current_level:
                current_level[b] = collections.OrderedDict()
            current_level = current_level[b]
        for c in obj.children:
            if c.raw not in current_level:
                current_level[c.raw] = collections.OrderedDict()

    def to_lines(self, section):
        lines = list()
        for entry in section[1:]:
            line = ['set']
            line.extend([p.text for p in entry.parents])
            line.append(entry.text)
            lines.append(' '.join(line))
        return lines

    def to_block(self, section):
        return '\n'.join([item.raw for item in section])

    def get_section(self, path):
        try:
            section = self.get_section_objects(path)
            if self._device_os == 'junos':
                return self.to_lines(section)
            return self.to_block(section)
        except ValueError:
            return list()

    def get_section_objects(self, path):
        if not isinstance(path, list):
            path = [path]
        obj = self.get_object(path)
        if not obj:
            raise ValueError('path does not exist in config')
        return self.expand_section(obj)

    def expand_section(self, configobj, S=None):
        if S is None:
            S = list()
        S.append(configobj)
        for child in configobj.children:
            if child in S:
                continue
            self.expand_section(child, S)
        return S

    def flatten(self, data, obj=None):
        if obj is None:
            obj = list()
        for k, v in data.items():
            obj.append(k)
            self.flatten(v, obj)
        return obj

    def get_object(self, path):
        for item in self.items:
            if item.text == path[-1]:
                parents = [p.text for p in item.parents]
                if parents == path[:-1]:
                    return item

    def get_children(self, path):
        obj = self.get_object(path)
        if obj:
            return obj.children

    def difference(self, other, path=None, match='line', replace='line'):
        updates = list()

        config = self.items
        if path:
            config = self.get_children(path) or list()

        if match == 'line':
            for item in config:
                if item not in other.items:
                    updates.append(item)

        elif match == 'strict':
            if path:
                current = other.get_children(path) or list()
            else:
                current = other.items

            for index, item in enumerate(config):
                try:
                    if item != current[index]:
                        updates.append(item)
                except IndexError:
                    updates.append(item)

        elif match == 'exact':
            if path:
                current = other.get_children(path) or list()
            else:
                current = other.items

            if len(current) != len(config):
                updates.extend(config)
            else:
                for ours, theirs in itertools.izip(config, current):
                    if ours != theirs:
                        updates.extend(config)
                        break

        if self._device_os == 'junos':
            return updates

        diffs = collections.OrderedDict()
        for update in updates:
            if replace == 'block' and update.parents:
                update = update.parents[-1]
            self.expand(update, diffs)

        return self.flatten(diffs)

    def replace(self, replace, text=None, regex=None, parents=None,
            add_if_missing=False, ignore_whitespace=False):
        match = None

        parents = parents or list()
        if text is None and regex is None:
            raise ValueError('missing required arguments')

        if not regex:
            regex = ['^%s$' % text]

        patterns = [re.compile(r, re.I) for r in to_list(regex)]

        for item in self.items:
            for regexp in patterns:
                string = item.text if ignore_whitespace is True else item.raw
                if regexp.search(item.text):
                    if item.text != replace:
                        if parents == [p.text for p in item.parents]:
                            match = item
                            break

        if match:
            match.text = replace
            indent = len(match.raw) - len(match.raw.lstrip())
            match.raw = replace.rjust(len(replace) + indent)

        elif add_if_missing:
            self.add(replace, parents=parents)


    def add(self, lines, parents=None):
        """Adds one or lines of configuration
        """

        ancestors = list()
        offset = 0
        obj = None

        ## global config command
        if not parents:
            for line in to_list(lines):
                item = ConfigLine(line)
                item.raw = line
                if item not in self.items:
                    self.items.append(item)

        else:
            for index, p in enumerate(parents):
                try:
                    i = index + 1
                    obj = self.get_section_objects(parents[:i])[0]
                    ancestors.append(obj)

                except ValueError:
                    # add parent to config
                    offset = index * self.indent
                    obj = ConfigLine(p)
                    obj.raw = p.rjust(len(p) + offset)
                    if ancestors:
                        obj.parents = list(ancestors)
                        ancestors[-1].children.append(obj)
                    self.items.append(obj)
                    ancestors.append(obj)

            # add child objects
            for line in to_list(lines):
                # check if child already exists
                for child in ancestors[-1].children:
                    if child.text == line:
                        break
                else:
                    offset = len(parents) * self.indent
                    item = ConfigLine(line)
                    item.raw = line.rjust(len(line) + offset)
                    item.parents = ancestors
                    ancestors[-1].children.append(item)
                    self.items.append(item)


def argument_spec():
    return dict(
        # config options
        running_config=dict(aliases=['config']),
        save_config=dict(type='bool', default=False, aliases=['save'])
    )
nxos_argument_spec = argument_spec()

def get_config(module):
    config = module.params['running_config']
    if not config:
        config = module.get_config()
    return CustomNetworkConfig(indent=2, contents=config)

def load_config(module, candidate):
    config = get_config(module)

    commands = candidate.difference(config)
    commands = [str(c).strip() for c in commands]

    save_config = module.params['save_config']

    result = dict(changed=False)

    if commands:
        if not module.check_mode:
            module.configure(commands)
            if save_config:
                module.config.save_config()

        result['changed'] = True
        result['updates'] = commands

    return result
# END OF COMMON CODE

import re
import collections


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def state_present(module, candidate, prefix):
    commands = list()
    invoke('set_route', module, commands, prefix)
    if commands:
        if module.params['vrf'] == 'default':
            candidate.add(commands, parents=[])
        else:
            candidate.add(commands, parents=['vrf context {0}'.format(module.params['vrf'])])


def state_absent(module, candidate, prefix):
    netcfg = get_config(module)
    commands = list()
    parents = 'vrf context {0}'.format(module.params['vrf'])
    invoke('set_route', module, commands, prefix)
    if module.params['vrf'] == 'default':
        config = netcfg.get_section(commands[0])
        if config:
            invoke('remove_route', module, commands, config, prefix)
            candidate.add(commands, parents=[])
    else:
        config = netcfg.get_section(parents)
        splitted_config = config.split('\n')
        splitted_config = map(str.strip, splitted_config)
        if commands[0] in splitted_config:
            invoke('remove_route', module, commands, config, prefix)
            candidate.add(commands, parents=[parents])


def fix_prefix_to_regex(prefix):
    prefix = prefix.split('.')
    prefix = '\.'.join(prefix)
    prefix = prefix.split('/')
    prefix = '\/'.join(prefix)

    return prefix


def get_existing(module, prefix, warnings):
    key_map = ['tag', 'pref', 'route_name', 'next_hop']
    netcfg = get_config(module)
    parents = 'vrf context {0}'.format(module.params['vrf'])
    prefix_to_regex = fix_prefix_to_regex(prefix)

    route_regex = '.*ip\sroute\s{0}\s(?P<next_hop>\S+)(\sname\s(?P<route_name>\S+))?(\stag\s(?P<tag>\d+))?(\s(?P<pref>\d+)).*'.format(prefix_to_regex)

    if module.params['vrf'] == 'default':
        config = str(netcfg)
    else:
        config = netcfg.get_section(parents)
    try:
        match_route = re.match(route_regex, config, re.DOTALL)
        group_route = match_route.groupdict()

        for key in key_map:
            if key not in group_route.keys():
                group_route['key'] = None
        group_route['prefix'] = prefix
    except (AttributeError, TypeError):
        group_route = {}
        if module.params['state'] == 'present':
            msg = ("VRF {0} doesn't exist.".format(module.params['vrf']))
            warnings.append(msg)

    return group_route


def remove_route(module, commands, config, prefix):
    commands.append('no ip route {0} {1}'.format(prefix, module.params['next_hop']))


def set_route(module, commands, prefix):
    route_cmd = 'ip route {0} {1}'.format(prefix, module.params['next_hop'])

    if module.params['route_name']:
        route_cmd += ' name {0}'.format(module.params['route_name'])
    if module.params['tag']:
        route_cmd += ' tag {0}'.format(module.params['tag'])
    if module.params['pref']:
        route_cmd += ' {0}'.format(module.params['pref'])
    commands.append(route_cmd)


def get_dotted_mask(mask):
    bits = 0
    for i in xrange(32-mask,32):
        bits |= (1 << i)
    mask = ("%d.%d.%d.%d" % ((bits & 0xff000000) >> 24,
           (bits & 0xff0000) >> 16, (bits & 0xff00) >> 8 , (bits & 0xff)))
    return mask


def get_network_start(address, netmask):
    address = address.split('.')
    netmask = netmask.split('.')
    return [str(int(address[x]) & int(netmask[x])) for x in range(0, 4)]


def network_from_string(address, mask, module):
    octects = address.split('.')

    if len(octects) > 4:
        module.fail_json(msg='Incorrect address format.', address=address)

    for octect in octects:
        try:
            if int(octect) < 0 or int(octect) > 255:
                module.fail_json(msg='Address may contain invalid values.',
                                 address=address)
        except ValueError:
            module.fail_json(msg='Address may contain non-integer values.',
                             address=address)

    try:
        if int(mask) < 0 or int(mask) > 32:
            module.fail_json(msg='Incorrect mask value.', mask=mask)
    except ValueError:
        module.fail_json(msg='Mask may contain non-integer values.', mask=mask)

    netmask = get_dotted_mask(int(mask))
    return '.'.join(get_network_start(address, netmask))


def normalize_prefix(module, prefix):
    splitted_prefix = prefix.split('/')

    if len(splitted_prefix) > 2:
        module.fail_json(msg='Incorrect address format.', address=address)
    elif len(splitted_prefix) == 2:
        address = splitted_prefix[0]
        mask = splitted_prefix[1]
        network = network_from_string(address, mask, module)

        normalized_prefix = str(network) + '/' + str(mask)
    else:
        normalized_prefix = prefix + '/' + str(32)

    return normalized_prefix


def main():
    argument_spec = dict(
        prefix=dict(required=True, type='str'),
        next_hop=dict(required=True, type='str'),
        vrf=dict(type='str', default='default'),
        tag=dict(type='str'),
        route_name=dict(type='str'),
        pref=dict(type='str'),
        m_facts=dict(required=False, default=False, type='bool'),
        state=dict(choices=['absent', 'present'],
                   default='present'),
        include_defaults=dict(default=True)
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    m_facts = module.params['m_facts']
    state = module.params['state']

    result = dict(changed=False)
    warnings = list()
    prefix = invoke('normalize_prefix', module, module.params['prefix'])

    existing = invoke('get_existing', module, prefix, warnings)
    end_state = existing

    args = ['route_name', 'vrf', 'pref', 'tag', 'next_hop', 'prefix']
    proposed = dict((k, v) for k, v in module.params.iteritems() if v is not None and k in args)

    if state == 'present' or (state == 'absent' and existing):
        candidate = CustomNetworkConfig(indent=3)
        invoke('state_%s' % state, module, candidate, prefix)

        try:
            response = load_config(module, candidate)
            result.update(response)
        except ShellError:
            exc = get_exception()
            module.fail_json(msg=str(exc))
    else:
        result['updates'] = []

    result['warnings'] = warnings
    result['connected'] = module.connected

    if module.params['m_facts']:
        end_state = invoke('get_existing', module, prefix, warnings)
        result['end_state'] = end_state
        result['existing'] = existing
        result['proposed'] = proposed

    module.exit_json(**result)



from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
