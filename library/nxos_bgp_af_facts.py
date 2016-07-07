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
module: nxos_bgp_af_facts
version_added: "2.2"
short_description: Retrieve BGP AF configuration
description:
    - Retrieve BGP AF configuration
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
options:
    asn:
        description:
            - BGP autonomous system number. Valid values are String,
              Integer in ASPLAIN or ASDOT notation.
        required: true
    vrf:
        description:
            - Name of the VRF. The name 'default' is a valid VRF representing the global bgp.
        required: true
    afi:
        description:
            - Address Family Identifier.
        required: true
        choices: ['ipv4','ipv6', 'vpnv4', 'vpnv6', 'l2vpn']
    safi:
        description:
            - Sub Address Family Identifier.
        required: true
        choices: ['unicast','multicast', 'evpn']
'''
EXAMPLES = '''
- nxos_bgp_af_facts:
    asn: 65512
    afi: ipv6
    safi: multicast
    vrf: test
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

WARNINGS = []
BOOL_PARAMS = [
    'additional_paths_install',
    'additional_paths_receive',
    'additional_paths_send',
    'advertise_l2vpn_evpn',
    'client_to_client',
    'dampening_state',
    'default_information_originate',
    'suppress_inactive',
    'table_map_filter'
]
PARAM_TO_COMMAND_KEYMAP = {
    'asn': 'router bgp',
    'afi': 'address-family',
    'safi': 'address-family',
    'additional_paths_install': 'additional-paths install backup',
    'additional_paths_receive': 'additional-paths receive',
    'additional_paths_selection': 'additional-paths selection route-map',
    'additional_paths_send': 'additional-paths send',
    'advertise_l2vpn_evpn': 'advertise l2vpn evpn',
    'client_to_client': 'client-to-client reflection',
    'dampen_igp_metric': 'dampen-igp-metric',
    'dampening_state': 'dampening',
    'dampening_half_time': 'dampening',
    'dampening_max_suppress_time': 'dampening',
    'dampening_reuse_time': 'dampening',
    'dampening_routemap': 'dampening route-map',
    'dampening_suppress_time': 'dampening',
    'default_information_originate': 'default-information-originate',
    'default_metric': 'default-metric',
    'distance_ebgp': 'default-metric',
    'distance_ibgp': 'default-metric',
    'distance_local': 'default-metric',
    'inject_map': 'inject-map',
    'maximum_paths': 'maximum-paths',
    'maximum_paths_ibgp': 'maximum-paths ibgp',
    'networks': 'network',
    'redistribute_direct': 'redistribute direct route-map',
    'redistribute_eigrp': 'redistribute eigrp route-map',
    'redistribute_hmm': 'redistribute hmm route-map',
    'redistribute_isis': 'redistribute isis route-map',
    'redistribute_ospf': 'redistribute ospf route-map',
    'redistribute_static': 'redistribute static route-map',
    'redistribute_rip': 'redistribute rip route-map',
    'redistribute_lisp': 'redistribute lisp route-map',
    'next_hop_route_map': 'nexthop route-map',
    'suppress_inactive': 'suppress-inactive',
    'table_map': 'table-map',
    'table_map_filter': 'table-map',
    'vrf': 'vrf'
}
ARGS =  [
    "additional_paths_install",
    "additional_paths_receive",
    "additional_paths_selection",
    "additional_paths_send",
    "advertise_l2vpn_evpn",
    "afi",
    "asn",
    "client_to_client",
    "dampen_igp_metric",
    "dampening_half_time",
    "dampening_max_suppress_time",
    "dampening_reuse_time",
    "dampening_suppress_time",
    "dampening_routemap",
    "dampening_state",
    "default_information_originate",
    "default_metric",
    "distance_ebgp",
    "distance_ibgp",
    "distance_local",
    "inject_map",
    "maximum_paths",
    "maximum_paths_ibgp",
    "networks",
    "next_hop_route_map",
    "redistribute_direct",
    "redistribute_eigrp",
    "redistribute_hmm",
    "redistribute_isis",
    "redistribute_ospf",
    "redistribute_static",
    "redistribute_rip",
    "redistribute_lisp",
    "safi",
    "suppress_inactive",
    "table_map",
    "table_map_filter",
    "vrf"
    ]

def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_custom_list_value(config, arg, module):
    splitted_config = config.splitlines()
    if arg == 'inject_map':
        value_list = []
        REGEX_INJECT = ('.*inject-map\s(?P<inject_map>\S+)'
                       '\sexist-map\s(?P<exist_map>\S+)-*')

        for line in splitted_config:
            value =  []
            inject_group = {}
            try:
                match_inject = re.match(REGEX_INJECT, line, re.DOTALL)
                inject_group = match_inject.groupdict()
                inject_map = inject_group['inject_map']
                exist_map = inject_group['exist_map']
                value.append(inject_map)
                value.append(exist_map)
            except AttributeError:
                value =  []

            if value:
                copy_attributes = False
                inject_map_command = ('inject-map {0} exist-map {1} '
                                      'copy-attributes'.format(
                                      inject_group['inject_map'],
                                      inject_group['exist_map']))

                REGEX = re.compile(r'\s+{0}\s*$'.format(
                                                inject_map_command), re.M)
                try:
                    if REGEX.search(config):
                        copy_attributes = True
                except TypeError:
                    copy_attributes = False

                if copy_attributes:
                    value.append('copy_attributes')
                value_list.append(value)

    elif arg == 'networks':
        value_list = []
        REGEX_NETWORK = re.compile(r'(?:network\s)(?P<value>.*)$')

        for line in splitted_config:
            value =  []
            network_group = {}
            if 'network' in line:
                value = REGEX_NETWORK.search(line).group('value').split()

                if value:
                    if len(value) == 3:
                        value.pop(1)
                    value_list.append(value)

    return value_list


def get_custom_string_value(config, arg, module):
    value = ''
    if arg.startswith('distance'):
        REGEX_DISTANCE = ('.*distance\s(?P<d_ebgp>\w+)\s(?P<d_ibgp>\w+)'
                          '\s(?P<d_local>\w+)')
        try:
            match_distance = re.match(REGEX_DISTANCE, config, re.DOTALL)
            distance_group = match_distance.groupdict()
        except AttributeError:
            distance_group = {}

        if distance_group:
            if arg == 'distance_ebgp':
                value = distance_group['d_ebgp']
            elif arg == 'distance_ibgp':
                value = distance_group['d_ibgp']
            elif arg == 'distance_local':
                value = distance_group['d_local']

    elif arg.startswith('dampening'):
        REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(
                                PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        if arg == 'dampen_igp_metric' or  arg == 'dampening_routemap':
            value = ''
            if PARAM_TO_COMMAND_KEYMAP[arg] in config:
                value = REGEX.search(config).group('value')
        else:
            REGEX_DAMPENING = ('.*dampening\s(?P<half>\w+)\s(?P<reuse>\w+)'
                              '\s(?P<suppress>\w+)\s(?P<max_suppress>\w+)')
            try:
                match_dampening = re.match(REGEX_DAMPENING, config, re.DOTALL)
                dampening_group = match_dampening.groupdict()
            except AttributeError:
                dampening_group = {}

            if dampening_group:
                if arg == 'dampening_half_time':
                    value = dampening_group['half']
                elif arg == 'dampening_reuse_time':
                    value = dampening_group['reuse']
                elif arg == 'dampening_suppress_time':
                    value = dampening_group['suppress']
                elif arg == 'dampening_max_suppress_time':
                    value = dampening_group['max_suppress']
    return value


def get_value(arg, config, module):
    custom = [
        'inject_map',
        'networks'
    ]

    if arg in BOOL_PARAMS:
        REGEX = re.compile(r'\s+{0}\s*$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = False
        try:
            if REGEX.search(config):
                value = True
        except TypeError:
            value = False

    elif arg in custom:
        value = get_custom_list_value(config, arg, module)

    elif arg.startswith('distance') or arg.startswith('dampening'):
        value = get_custom_string_value(config, arg, module)

    else:
        REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = ''
        if PARAM_TO_COMMAND_KEYMAP[arg] in config:
            value = REGEX.search(config).group('value')
    return value


def get_existing(module):
    existing = {}
    netcfg = get_config(module)

    try:
        asn_regex = '.*router\sbgp\s(?P<existing_asn>\d+).*'
        match_asn = re.match(asn_regex, str(netcfg), re.DOTALL)
        existing_asn_group = match_asn.groupdict()
        existing_asn = existing_asn_group['existing_asn']
    except AttributeError:
        existing_asn = ''

    if existing_asn:
        parents = ["router bgp {0}".format(existing_asn)]
        if module.params['vrf'] != 'default':
            parents.append('vrf {0}'.format(module.params['vrf']))

        parents.append('address-family {0} {1}'.format(module.params['afi'],
                                                module.params['safi']))
        config = netcfg.get_section(parents)
        if config:
            for arg in ARGS:
                if arg not in ['asn', 'afi', 'safi', 'vrf']:
                    existing[arg] = get_value(arg, config, module)

            existing['asn'] = existing_asn
            existing['afi'] = module.params['afi']
            existing['safi'] = module.params['safi']
            existing['vrf'] = module.params['vrf']

    return existing


def main():
    argument_spec = dict(
            asn=dict(required=True, type='str'),
            vrf=dict(required=False, type='str', default='default'),
            safi=dict(required=True, type='str', choices=['unicast','multicast', 'evpn']),
            afi=dict(required=True, type='str', choices=['ipv4','ipv6', 'vpnv4', 'vpnv6', 'l2vpn']),
            include_defaults=dict(default=True)
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    if existing.get('asn'):
        if existing.get('asn') != module.params['asn']:
            WARNINGS.append('Another BGP ASN exists on the device.  '
                            'ASN:{0}'.format(existing.get('asn')))

    bgp_af_facts = dict(nxos_bgp_af_facts=existing)
    module.exit_json(ansible_facts=bgp_af_facts,
                     changed=False,
                     warnings=WARNINGS)




from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
