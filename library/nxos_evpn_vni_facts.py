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
module: nxos_evpn_vni_facts
version_added: "2.2"
short_description: Retrieve Cisco EVPN VXLAN Network Identifier (VNI)
description:
    - Retrieve Cisco Ethernet Virtual Private Network (EVPN) VXLAN Network
      Identifier (VNI) configurations of a Nexus device.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
options:
    vni:
        description:
            - The EVPN VXLAN Network Identifier.
        required: true
'''
EXAMPLES = '''
- nxos_evpn_vni_facts:
    vni: 6000
'''

PARAM_TO_COMMAND_KEYMAP = {
    'vni': 'vni',
    'route_target_both': 'route-target both',
    'route_target_import': 'route-target import',
    'route_target_export': 'route-target export',
    'route_distinguisher': 'rd'
}
ARGS =  [
        'vni',
        'route_distinguisher',
        'route_target_both',
        'route_target_import',
        'route_target_export'
    ]

def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_value(arg, config, module):
    REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
    value = ''
    if PARAM_TO_COMMAND_KEYMAP[arg] in config:
        value = REGEX.search(config).group('value')
    return value


def get_route_target_value(arg, config, module):
    splitted_config = config.splitlines()
    value_list = []
    REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)

    for line in splitted_config:
        value = ''
        if PARAM_TO_COMMAND_KEYMAP[arg] in line.strip():
            value = REGEX.search(line).group('value')
            value_list.append(value)
    return value_list


def get_existing(module):
    existing = {}
    netcfg = get_config(module)
    parents = ['evpn', 'vni {0} l2'.format(module.params['vni'])]
    config = netcfg.get_section(parents)

    if config:
        for arg in ARGS:
            if arg != 'vni':
                if arg == 'route_distinguisher':
                    existing[arg] = get_value(arg, config, module)
                else:
                    existing[arg] = get_route_target_value(arg, config, module)

        existing_fix = dict((k, v) for k, v in existing.iteritems() if v)
        if existing_fix:
            existing['vni'] = module.params['vni']
        else:
            existing = existing_fix

    return existing


def main():
    argument_spec = dict(
            vni=dict(required=True, type='str')
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    evpn_vni_facts = dict(evpn_vni_facts=existing)
    module.exit_json(ansible_facts=evpn_vni_facts,
                     changed=False)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
