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
module: nxos_vrf
version_added: "2.1"
short_description: Manages global VRF configuration
description:
    - Manages global VRF configuration
extends_documentation_fragment: nxos
author: Jason Edelman (@jedelman8), Gabriele Gerbino (@GGabriele)
notes:
    - Cisco NX-OS creates the default VRF by itself. Therefore,
      you're not allowed to use default as I(vrf) name in this module.
    - I(vrf) name must be shorter than 32 chars.
    - VRF names are not case sensible in NX-OS. Anyway, the name is stored
      just like it's inserted by the user and it'll not be changed again
      unless the VRF is removed and re-created. i.e. I(vrf=NTC) will create
      a VRF named NTC, but running it again with I(vrf=ntc) will not cause
      a configuration change.
options:
    vrf:
        description:
            - Name of VRF to be managed
        required: true
    admin_state:
        description:
            - Administrative state of the VRF
        required: false
        default: up
        choices: ['up','down']
    vni:
        description:
            - Specify virtual network identifier. Valid values are Integer
              or keyword 'default'.
        required: false
        default: null
    route_distinguisher:
        description:
            -  VPN Route Distinguisher (RD). Valid values are a string in
               one of the route-distinguisher formats (ASN2:NN, ASN4:NN, or
               IPV4:NN); the keyword 'auto', or the keyword 'default'.
        required: false
        default: null
    state:
        description:
            - Manages desired state of the resource
        required: false
        default: present
        choices: ['present','absent']
    description:
        description:
            - Description of the VRF
        required: false
        default: null
'''

EXAMPLES = '''
# ensure ntc VRF exists on switch
- nxos_vrf: vrf=ntc host=68.170.147.165
# ensure ntc VRF does not exist on switch
- nxos_vrf: vrf=ntc host=68.170.147.165 state=absent
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"admin_state": "Up", "description": "Test test",
            "vrf": "ntc"}
existing:
    description: k/v pairs of existing vrf
    type: dict
    sample: {"admin_state": "Up", "description": "Old test",
            "vrf": "old_ntc"}
end_state:
    description: k/v pairs of vrf info after module execution
    returned: always
    type: dict
    sample: {"admin_state": "Up", "description": "Test test",
            "vrf": "ntc"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
updates:
    description: commands sent to the device
    returned: always
    type: list
    sample: ["vrf context ntc", "shutdown"]
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
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

def execute_config_command(commands, module):
    try:
        module.configure(commands)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending CLI commands',
                         error=str(clie), commands=commands)


def get_cli_body_ssh_vrf(command, response):
    """Get response for when transport=cli.  This is kind of a hack and mainly
    needed because these modules were originally written for NX-API.  And
    not every command supports "| json" when using cli/ssh.  As such, we assume
    if | json returns an XML string, it is a valid command, but that the
    resource doesn't exist yet. Instead, the output will be a raw string
    when using multiple |.
    """
    command_splitted = command.split('|')
    if len(command_splitted) > 2:
        body = response
    elif 'xml' in response[0]:
        body = []
    else:
        body = [json.loads(response[0])]
    return body


def execute_show(cmds, module, command_type=None):
    try:
        if command_type:
            response = module.execute(cmds, command_type=command_type)
        else:
            response = module.execute(cmds)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending {0}'.format(cmds),
                         error=str(clie))
    return response


def execute_show_command(command, module, command_type='cli_show'):
    if module.params['transport'] == 'cli':
        command += ' | json'
        cmds = [command]
        response = execute_show(cmds, module)
        body = get_cli_body_ssh_vrf(command, response)
    elif module.params['transport'] == 'nxapi':
        cmds = [command]
        body = execute_show(cmds, module, command_type=command_type)

    return body


def apply_key_map(key_map, table):
    new_dict = {}
    for key, value in table.items():
        new_key = key_map.get(key)
        if new_key:
            value = table.get(key)
            if value:
                new_dict[new_key] = str(value)
            else:
                new_dict[new_key] = value
    return new_dict


def get_commands_to_config_vrf(delta, vrf):
    commands = []
    for param, value in delta.iteritems():
        command = ''
        if param == 'description':
            command = 'description {0}'.format(value)
        elif param == 'admin_state':
            if value.lower() == 'up':
                command = 'no shutdown'
            elif value.lower() == 'down':
                command = 'shutdown'
        elif param == 'rd':
            command = 'rd {0}'.format(value)
        elif param == 'vni':
            command = 'vni {0}'.format(value)
        if command:
            commands.append(command)
    if commands:
        commands.insert(0, 'vrf context {0}'.format(vrf))
    return commands


def get_vrf_description(vrf, module):
    command_type = 'cli_show_ascii'
    command = ('show run section vrf | begin ^vrf\scontext\s{0} '
               '| end ^vrf.*'.format(vrf))

    description = ''
    descr_regex = ".*description\s(?P<descr>[\S+\s]+).*"
    body = execute_show_command(command, module, command_type)

    try:
        body = body[0]
        splitted_body = body.split('\n')
    except (AttributeError, IndexError):
        return description

    for element in splitted_body:
        if 'description' in element:
            match_description = re.match(descr_regex, element,
                                         re.DOTALL)
            group_description = match_description.groupdict()
            description = group_description["descr"]

    return description


def get_value(arg, config, module):
    REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(arg), re.M)
    value = ''
    if arg in config:
        value = REGEX.search(config).group('value')
    return value


def get_vrf(vrf, module):
    command = 'show vrf {0}'.format(vrf)
    vrf_key = {
        'vrf_name': 'vrf',
        'vrf_state': 'admin_state'
        }

    body = execute_show_command(command, module)
    try:
        vrf_table = body[0]['TABLE_vrf']['ROW_vrf']
    except (TypeError, IndexError):
        return {}

    parsed_vrf = apply_key_map(vrf_key, vrf_table)

    command = 'show run all | section vrf.context.{0}'.format(vrf)
    body = execute_show_command(command, module, 'cli_show_ascii')
    extra_params = ['vni', 'rd', 'description']
    for param in extra_params:
        parsed_vrf[param] = get_value(param, body[0], module)

    return parsed_vrf


def main():
    argument_spec = dict(
            vrf=dict(required=True),
            description=dict(default=None, required=False),
            vni=dict(required=False, type='str'),
            rd=dict(required=False, type='str'),
            admin_state=dict(default='up', choices=['up', 'down'],
                             required=False),
            state=dict(default='present', choices=['present', 'absent'],
                       required=False),
    )
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    vrf = module.params['vrf']
    admin_state = module.params['admin_state'].lower()
    description = module.params['description']
    rd = module.params['rd']
    vni = module.params['vni']
    state = module.params['state']

    if vrf == 'default':
        module.fail_json(msg='cannot use default as name of a VRF')
    elif len(vrf) > 32:
        module.fail_json(msg='VRF name exceeded max length of 32',
                         vrf=vrf)

    existing = get_vrf(vrf, module)
    args = dict(vrf=vrf, description=description, vni=vni,
                admin_state=admin_state, rd=rd)

    end_state = existing
    changed = False
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    """Since 'admin_state' is either 'Up' or 'Down' from outputs,
    we use the following to make sure right letter case is used so that delta
    results will be consistent to the actual configuration."""
    if existing:
        if existing['admin_state'].lower() == admin_state:
            proposed['admin_state'] = existing['admin_state']

    delta = dict(set(proposed.iteritems()).difference(existing.iteritems()))
    changed = False
    end_state = existing
    commands = []
    if state == 'absent':
        if existing:
            command = ['no vrf context {0}'.format(vrf)]
            commands.extend(command)

    elif state == 'present':
        if not existing:
            command = get_commands_to_config_vrf(delta, vrf)
            commands.extend(command)
        elif delta:
                command = get_commands_to_config_vrf(delta, vrf)
                commands.extend(command)

    if commands:
        if proposed.get('vni'):
            if existing.get('vni') and existing.get('vni') != '':
                commands.insert(1, 'no vni {0}'.format(existing['vni']))
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            execute_config_command(commands, module)
            changed = True
            end_state = get_vrf(vrf, module)

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['end_state'] = end_state
    results['state'] = state
    results['updates'] = commands
    results['changed'] = changed

    module.exit_json(**results)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
