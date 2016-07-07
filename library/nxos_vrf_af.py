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
module: nxos_vxlan_vtep_vni
version_added: "2.2"
short_description: Creates a Virtual Network Identifier member (VNI)
description:
    - Creates a Virtual Network Identifier member (VNI) for an NVE
      overlay interface.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - 'default' restores params default value
options:
    vrf:
        description:
            - Name of the VRF.
        required: true
    afi:
        description:
            - Address-Family Identifier (AFI).
        required: true
        choices: ['ipv4', 'ipv6']
        default: null
    safi:
        description:
            - Sub Address-Family Identifier (SAFI).
        required: true
        choices: ['unicast', 'multicast']
        default: null
    route_target_both_auto_evpn:
        description:
            - Enable/Disable the EVPN route-target 'auto' setting for both
              import and export target communities.
        required: false
        choices: ['true', 'false', 'default']
        default: null
    state:
        description:
            - Determines whether the config should be present or not on the device.
        required: false
        default: present
        choices: ['present','absent']
    m_facts:
        description:
            - Used to print module facts
        required: false
        default: false
        choices: ['true','false']
'''
EXAMPLES = '''
- nxos_vxlan_vtep_vni:
    interface=nve1
    vni=6000
    ingress_replication=default
'''

BOOLEANS_TRUE = ['yes', 'on', '1', 'true', 'True', 1, True]
BOOLEANS_FALSE = ['no', 'off', '0', 'false', 'False', 0, False]
ACCEPTED = BOOLEANS_TRUE + BOOLEANS_FALSE + ['default']
BOOL_PARAMS = ['route_target_both_auto_evpn']
PARAM_TO_COMMAND_KEYMAP = {
    'route_target_both_auto_evpn': 'route-target both auto evpn',
}
PARAM_TO_DEFAULT_KEYMAP = {}
WARNINGS = []

def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_value(arg, config, module):
    if arg in BOOL_PARAMS:
        REGEX = re.compile(r'\s+{0}\s*$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = False
        try:
            if REGEX.search(config):
                value = True
        except TypeError:
            value = False
    else:
        REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = ''
        if PARAM_TO_COMMAND_KEYMAP[arg] in config:
            value = REGEX.search(config).group('value')
    return value


def get_existing(module, args):
    existing = {}
    netcfg = get_config(module)

    parents = ['vrf context {0}'.format(module.params['vrf'])]
    parents.append('address-family {0} {1}'.format(module.params['afi'],
                                            module.params['safi']))
    config = netcfg.get_section(parents)
    if config:
        splitted_config = config.splitlines()
        vrf_index = False
        for index in range(0, len(splitted_config) - 1):
            if 'vrf' in splitted_config[index].strip():
                    vrf_index = index
                    break
        if vrf_index:
            config = '\n'.join(splitted_config[0:vrf_index])

        for arg in args:
            if arg not in ['afi', 'safi', 'vrf']:
                existing[arg] = get_value(arg, config, module)

        existing['afi'] = module.params['afi']
        existing['safi'] = module.params['safi']
        existing['vrf'] = module.params['vrf']

    return existing


def apply_key_map(key_map, table):
    new_dict = {}
    for key, value in table.items():
        new_key = key_map.get(key)
        if new_key:
            value = table.get(key)
            if value:
                new_dict[new_key] = value
            else:
                new_dict[new_key] = value
    return new_dict


def state_present(module, existing, proposed, candidate):
    commands = list()
    proposed_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, proposed)
    existing_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, existing)

    for key, value in proposed_commands.iteritems():
        if value is True:
            commands.append(key)

        elif value is False:
            commands.append('no {0}'.format(key))

        elif value == 'default':
            if existing_commands.get(key):
                existing_value = existing_commands.get(key)
                commands.append('no {0} {1}'.format(key, existing_value))

            else:
                if key.replace(' ', '_').replace('-', '_') in BOOL_PARAMS:
                    commands.append('no {0}'.format(key.lower()))
        else:
            command = '{0} {1}'.format(key, value.lower())
            commands.append(command)

    if commands:
        parents = ['vrf context {0}'.format(module.params['vrf'])]
        parents.append('address-family {0} {1}'.format(module.params['afi'],
                                                module.params['safi']))
        candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    commands = []
    parents = ['vrf context {0}'.format(module.params['vrf'])]
    commands.append('no address-family {0} {1}'.format(module.params['afi'],
                                                module.params['safi']))
    candidate.add(commands, parents=parents)


def main():
    argument_spec = dict(
            vrf=dict(required=True, type='str'),
            safi=dict(required=True, type='str', choices=['unicast','multicast']),
            afi=dict(required=True, type='str', choices=['ipv4','ipv6']),
            route_target_both_auto_evpn=dict(required=False, choices=ACCEPTED),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']

    args =  [
            'vrf',
            'safi',
            'afi',
            'route_target_both_auto_evpn'
        ]

    existing = invoke('get_existing', module, args)
    end_state = existing
    proposed_args = dict((k, v) for k, v in module.params.iteritems()
                    if v is not None and k in args)

    proposed = {}
    for key, value in proposed_args.iteritems():
        if key != 'interface':
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.lower() == 'default':
                value = PARAM_TO_DEFAULT_KEYMAP.get(key)
                if value is None:
                    if key in BOOL_PARAMS:
                        value = False
                    else:
                        value = 'default'
            if existing.get(key) or (not existing.get(key) and value):
                proposed[key] = value

    result = {}
    if state == 'present' or (state == 'absent' and existing):
        candidate = NetworkConfig(indent=3)
        invoke('state_%s' % state, module, existing, proposed, candidate)

        try:
            response = load_config(module, candidate)
            result.update(response)
        except NetworkError:
            exc = get_exception()
            module.fail_json(msg=str(exc))
    else:
        result['updates'] = []

    result['connected'] = module.connected
    if module.params['m_facts']:
        end_state = invoke('get_existing', module, args)
        result['end_state'] = end_state
        result['existing'] = existing
        result['proposed'] = proposed_args

    if WARNINGS:
        result['warnings'] = WARNINGS

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
