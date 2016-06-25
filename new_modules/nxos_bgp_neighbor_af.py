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
module: nxos_bgp_neighbor_af
version_added: "2.2"
short_description: Manages BGP address-family's neighbors configuration
description:
    - Manages BGP address-family's neighbors configurations on NX-OS switches
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - State 'absent' removes the whole BGP address-family's neighbor configuration
options:
    asn:
        description:
            - BGP autonomous system number. Valid values are String,
              Integer in ASPLAIN or ASDOT notation.
        required: true
    vrf:
        description:
            - Name of the VRF. The name 'default' is a valid VRF representing
              the global bgp.
        required: false
        default: default
    neighbor:
        description:
            - Neighbor Identifier. Valid values are string. Neighbors may use
              IPv4 or IPv6 notation, with or without prefix length.
        required: true
    afi:
        description:
            - Address Family Identifie.
        required: true
        choices: ['ipv4','ipv6', 'vpnv4', 'vpnv6', 'l2vpn']
    safi:
        description:
            - Sub Address Family Identifier.
        required: true
        choices: ['unicast','multicast', 'evpn']
    route_reflector_client:
        description:
            - Router reflector client.
        required: false
        choices: ['true','false', 'default']
        default: null
    send_community:
        description:
            - send-community attribute.
        required: false
        choices: ['none', 'both', 'extended', 'standard', 'default']
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
- cisco_bgp_neighbor:
    asn=65535
    neighbor=2.2.2.2
    afi=ipv4
    safi=multicast
    send_community=both
    state: present
'''

ACCEPTED = ['true','false', 'default']
BOOL_PARAMS = [
    'route_reflector_client'
]
PARAM_TO_COMMAND_KEYMAP = {
    'afi': 'address-family',
    'asn': 'router bgp',
    'neighbor': 'neighbor',
    'route_reflector_client': 'route-reflector-client',
    'safi': 'address-family',
    'send_community': 'send-community',
    'vrf': 'vrf'
}
PARAM_TO_DEFAULT_KEYMAP = {}


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


def get_custom_value(arg, config, module):
    splitted_config = config.splitlines()
    REGEX = '.*send-community(\s(?P<modifier>\w+)).*'
    value = ''

    for line in splitted_config:
        if 'send-community' in line:
            splitted_line = line.split()
            if len(splitted_line) == 1:
                value = 'none'
            else:
                value = splitted_line[1]
    return value


def get_existing(module, args):
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

        parents.append('neighbor {0}'.format(module.params['neighbor']))
        parents.append('address-family {0} {1}'.format(
                            module.params['afi'], module.params['safi']))
        config = netcfg.get_section(parents)

        if config:
            for arg in args:
                if arg == 'route_reflector_client':
                    existing[arg] = get_value(arg, config, module)
                elif arg == 'send_community':
                    existing[arg] = get_custom_value(arg, config, module)

            existing['asn'] = existing_asn
            existing['neighbor'] = module.params['neighbor']
            existing['vrf'] = module.params['vrf']
            existing['afi'] = module.params['afi']
            existing['safi'] = module.params['safi']

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
        if key == 'address-family':
            addr_family_command = "address-family {0} {1}".format(
                            module.params['afi'], module.params['safi'])
            if addr_family_command not in commands:
                commands.append(addr_family_command)

        elif key == 'send-community' and value == 'none':
            commands.append('{0}'.format(key))

        elif value is True:
            commands.append(key)

        elif value is False:
            commands.append('no {0}'.format(key))

        elif value == 'default':
            if key == 'send-community' and existing_commands[key] == 'none':
                commands.append('no {0}'.format(key))

            elif existing_commands.get(key):
                existing_value = existing_commands.get(key)
                commands.append('no {0} {1}'.format(key, existing_value))

            else:
                if key.replace(' ', '_').replace('-', '_') in BOOL_PARAMS:
                    commands.append('no {0}'.format(key))
        else:
            command = '{0} {1}'.format(key, value)
            commands.append(command)

    if commands:
        parents = ["router bgp {0}".format(module.params['asn'])]
        if module.params['vrf'] != 'default':
            parents.append('vrf {0}'.format(module.params['vrf']))

        parents.append('neighbor {0}'.format(module.params['neighbor']))

        if len(commands) == 1:
            candidate.add(commands, parents=parents)
        elif len(commands) > 1:
            af_command = 'address-family {0} {1}'.format(
                                module.params['afi'], module.params['safi'])
            if af_command in commands:
                commands.remove(af_command)
                parents.append('address-family {0} {1}'.format(
                                module.params['afi'], module.params['safi']))
                candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    commands = []
    parents = ["router bgp {0}".format(module.params['asn'])]
    if module.params['vrf'] != 'default':
        parents.append('vrf {0}'.format(module.params['vrf']))

    parents.append('neighbor {0}'.format(module.params['neighbor']))
    commands.append('no address-family {0} {1}'.format(
                        module.params['afi'], module.params['safi']))
    candidate.add(commands, parents=parents)


def main():
    argument_spec = dict(
            asn=dict(required=True, type='str'),
            vrf=dict(required=False, type='str', default='default'),
            neighbor=dict(required=True, type='str'),
            afi=dict(required=False, type='str'),
            safi=dict(required=False, type='str'),
            route_reflector_client=dict(required=False, choices=ACCEPTED),
            send_community=dict(required=False, choices=['none',
                                                         'both',
                                                         'extended',
                                                         'standard',
                                                         'default']),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']

    args =  [
            'afi',
            'asn',
            'neighbor',
            'route_reflector_client',
            'safi',
            'send_community',
            'vrf'
        ]

    existing = invoke('get_existing', module, args)

    if existing.get('asn'):
        if (existing.get('asn') != module.params['asn'] and
            state == 'present'):
            module.fail_json(msg='Another BGP ASN already exists.',
                             proposed_asn=module.params['asn'],
                             existing_asn=existing.get('asn'))

    end_state = existing
    proposed_args = dict((k, v) for k, v in module.params.iteritems()
                    if v is not None and k in args)

    proposed = {}
    for key, value in proposed_args.iteritems():
        if key not in ['asn', 'vrf', 'neighbor']:
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

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
