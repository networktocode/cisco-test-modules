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
module: nxos_vxlan_vtep_facts
version_added: "2.2"
short_description: Retrieve VXLAN Network Virtualization Endpoint (NVE)
description:
    - Retrieve VXLAN Network Virtualization Endpoint (NVE) overlay interface
      that terminates VXLAN tunnels.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
options:
    interface:
        description:
            - Interface name for the VXLAN Network Virtualization Endpoint
        required: true
'''
EXAMPLES = '''
- nxos_vxlan_vtep_facts:
    interface=nve1
'''

BOOL_PARAMS = [
    'shutdown',
    'host_reachability'
]
PARAM_TO_COMMAND_KEYMAP = {
    'description': 'description',
    'host_reachability': 'host-reachability protocol bgp',
    'interface': 'interface',
    'shutdown': 'shutdown',
    'source_interface': 'source-interface',
    'source_interface_hold_down_time': 'source-interface hold-down-time'
}
ARGS =  [
    'interface',
    'description',
    'host_reachability',
    'shutdown',
    'source_interface',
    'source_interface_hold_down_time'
    ]

def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_value(arg, config, module):
    if arg in BOOL_PARAMS:
        REGEX = re.compile(r'\s+{0}\s*$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        NO_SHUT_REGEX = re.compile(r'\s+no shutdown\s*$', re.M)
        value = False
        if arg == 'shutdown':
            try:
                if NO_SHUT_REGEX.search(config):
                    value = False
                elif REGEX.search(config):
                    value = True
            except TypeError:
                value = False
        else:
            try:
                if REGEX.search(config):
                    value = True
            except TypeError:
                value = False
    else:
        REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        NO_DESC_REGEX = re.compile(r'\s+{0}\s*$'.format('no description'), re.M)
        SOURCE_INTF_REGEX = re.compile(r'(?:{0}\s)(?P<value>\S+)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = ''
        if arg == 'description':
            if NO_DESC_REGEX.search(config):
                value = ''
            elif PARAM_TO_COMMAND_KEYMAP[arg] in config:
                value = REGEX.search(config).group('value').strip()
        elif arg == 'source_interface':
            for line in config.splitlines():
                try:
                    if PARAM_TO_COMMAND_KEYMAP[arg] in config:
                        value = SOURCE_INTF_REGEX.search(config).group('value').strip()
                        break
                except AttributeError:
                    value = ''
        else:
            if PARAM_TO_COMMAND_KEYMAP[arg] in config:
                value = REGEX.search(config).group('value').strip()
    return value


def get_existing(module):
    existing = {}
    netcfg = get_config(module)

    parents = ['interface {0}'.format(module.params['interface'].lower())]
    config = netcfg.get_section(parents)

    if config:
        for arg in ARGS:
            existing[arg] = get_value(arg, config, module)

        existing['interface'] = module.params['interface'].lower()
    return existing


def main():
    argument_spec = dict(
            interface=dict(required=True, type='str'),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    vxlan_vtep_facts = dict(vxlan_vtep_facts=existing)
    module.exit_json(ansible_facts=vxlan_vtep_facts,
                     changed=False)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
