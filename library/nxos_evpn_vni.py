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
module: nxos_evpn_vni
version_added: "2.2"
short_description: Manages Cisco EVPN VXLAN Network Identifier (VNI)
description:
    - Manages Cisco Ethernet Virtual Private Network (EVPN) VXLAN Network
      Identifier (VNI) configurations of a Nexus device.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - 'default' restores params default value
    - route_target_both, route_target_import and route_target_export valid
      values are a list of extended communities, (i.e. ['1.2.3.4:5', '33:55'])
      or the keywords 'auto' or 'default'.
    - The route_target_both property is discouraged due to the inconsistent
      behavior of the property across Nexus platforms and image versions.
      For this reason it is recommended to use explicit 'route_target_export'
      and 'route_target_import' properties instead of route_target_both.
    - RD valid values are a String in one of the route-distinguisher formats
      (ASN2:NN, ASN4:NN, or IPV4:NN); the keyword 'auto', or the keyword
      'default'.
options:
    vni:
        description:
            - The EVPN VXLAN Network Identifier.
        required: true
        default: null
    route_distinguisher:
        description:
            - The VPN Route Distinguisher (RD). The RD is combined with
              the IPv4 or IPv6 prefix learned by the PE router to create a
              globally unique address.
        required: true
        default: null
    route_target_both:
        description:
            - Enables/Disables route-target settings for both import and
              export target communities using a single property.
        required: false
        default: null
    route_target_import:
        description:
            - Sets the route-target 'import' extended communities.
        required: false
        default: null
    route_target_export:
        description:
            - Sets the route-target 'import' extended communities.
        required: false
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
- nxos_evpn_vni:
    vni: 6000
    route_distinguisher: "60:10"
    route_target_import:
        - "5000:10"
        - "4100:100"
    route_target_export: auto
    route_target_both: default
'''

PARAM_TO_COMMAND_KEYMAP = {
    'vni': 'vni',
    'route_target_both': 'route-target both',
    'route_target_import': 'route-target import',
    'route_target_export': 'route-target export',
    'route_distinguisher': 'rd'
}


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


def get_existing(module, args):
    existing = {}
    netcfg = get_config(module)
    parents = ['evpn', 'vni {0} l2'.format(module.params['vni'])]
    config = netcfg.get_section(parents)

    if config:
        for arg in args:
            if arg != 'vni':
                if arg == 'route_distinguisher':
                    existing[arg] = get_value(arg, config, module)
                else:
                    existing[arg] = get_route_target_value(arg, config, module)
        existing['vni'] = module.params['vni']

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
        if key.startswith('route-target'):
            if value == ['default']:
                existing_value = existing_commands.get(key)

                if existing_value:
                    for target in existing_value:
                        commands.append('no {0} {1}'.format(key, target))
            else:
                if not isinstance(value, list):
                    value = [value]
                for target in value:
                    if existing:
                        if target not in existing.get(key.replace('-', '_').replace(' ', '_')):
                            commands.append('{0} {1}'.format(key, target))
                    else:
                        commands.append('{0} {1}'.format(key, target))
        else:
            if value == 'default':
                existing_value = existing_commands.get(key)
                if existing_value:
                    commands.append('no {0} {1}'.format(key, existing_value))
            else:
                command = '{0} {1}'.format(key, value)
                commands.append(command)

    if commands:
        parents = ['evpn', 'vni {0} l2'.format(module.params['vni'])]
        candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    commands = ['no vni {0} l2'.format(module.params['vni'])]
    parents = ['evpn']
    candidate.add(commands, parents=parents)


def main():
    argument_spec = dict(
            vni=dict(required=True, type='str'),
            route_distinguisher=dict(required=False, type='str'),
            route_target_both=dict(required=False, type='list'),
            route_target_import=dict(required=False, type='list'),
            route_target_export=dict(required=False, type='list'),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']
    args =  [
            'vni',
            'route_distinguisher',
            'route_target_both',
            'route_target_import',
            'route_target_export'
        ]

    existing = invoke('get_existing', module, args)
    end_state = existing
    proposed_args = dict((k, v) for k, v in module.params.iteritems()
                    if v is not None and k in args)

    proposed = {}
    for key, value in proposed_args.iteritems():
        if key != 'vni':
            if value == 'true':
                value = True
            elif value == 'false':
                value = False
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

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()