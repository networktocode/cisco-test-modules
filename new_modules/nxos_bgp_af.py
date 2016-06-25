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
module: nxos_bgp_af
version_added: "2.2"
short_description: Manages BGP Address-family configuration
description:
    - Manages BGP Address-family configurations on NX-OS switches
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - State 'absent' removes the whole BGP ASN configuration
    - 'default' restores params default value
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
            - Address Family Identifie.
        required: true
        choices: ['ipv4','ipv6', 'vpnv4', 'vpnv6', 'l2vpn']
    safi:
        description:
            - Sub Address Family Identifier.
        required: true
        choices: ['unicast','multicast', 'evpn']
    additional_paths_install:
        description:
            - Install a backup path into the forwarding table and provide
              prefix 'independent convergence (PIC) in case of a PE-CE link
              failure.
        required: false
        choices: ['true','false', 'default']
        default: null
    additional_paths_receive:
        description:
            - Enables the receive capability of additional paths for all of
              the neighbors under this address family for which the capability
              has not been disabled.
        required: false
        choices: ['true','false', 'default']
        default: null
    additional_paths_selection:
        description:
            - Configures the capability of selecting additional paths for
              a prefix.
        required: false
        default: null
    additional_paths_send:
        description:
            - Enables the send capability of additional paths for all of
              the neighbors under this address family for which the capability
              has not been disabled.
        required: false
        choices: ['true','false', 'default']
        default: null
    advertise_l2vpn_evpn:
        description:
            - Advertise evpn routes.
        required: false
        choices: ['true','false']
        default: null
    client_to_client:
        description:
            - Configure client-to-client route reflection.
        required: false
        choices: ['true','false']
        default: null
    dampen_igp_metric:
        description:
            - Specify dampen value for IGP metric-related changes, in seconds.
        required: false
        default: null
    dampening_state:
        description:
            - Enable/disable route-flap dampening.
        required: false
        choices: ['true','false', 'default']
        default: null
    dampening_half_time:
        description:
            - Specify decay half-life in minutes for route-flap dampening.
        required: false
        default: null
    dampening_max_suppress_time:
        description:
            - Specify max suppress time for route-flap dampening stable route.
        required: false
        default: null
    dampening_reuse_time:
        description:
            - Specify route reuse time for route-flap dampening.
        required: false
    dampening_routemap:
        description:
            - Specify route-map for route-flap dampening.
        required: false
        default: null
    dampening_suppress_time:
        description:
            - Specify route suppress time for route-flap dampening.
        required: false
        default: null
    default_information_originate:
        description:
            - Default information originate
        required: false
        choices: ['true','false']
        default: null
    default_metric:
        description:
            - Sets default metrics for routes redistributed into BGP.
        required: false
        default: null
    distance_ebgp:
        description:
            - Sets the administrative distance for eBGP routes.
        required: false
        default: null
    distance_ibgp:
        description:
            - Sets the administrative distance for iBGP routes.
        required: false
        default: null
    distance_local:
        description:
            - Sets the administrative distance for local BGP routes.
        required: false
        default: null
    inject_map:
        description:
            - An array of route-map names which will specify prefixes to
              inject. Each array entry must first specify the inject-map name,
              secondly an exist-map name, and optionally the copy-attributes
              keyword which indicates that attributes should be copied from
              the aggregate. Example: [['lax_inject_map', 'lax_exist_map'],
              ['nyc_inject_map', 'nyc_exist_map', 'copy-attributes'],
              ['fsd_inject_map', 'fsd_exist_map']]
        required: false
        default: null
    maximum_paths:
        description:
            - Configures the maximum number of equal-cost paths for
              load sharing. Valid value is an integer in the range 1-64.
        default: null
    maximum_paths_ibgp:
        description:
            - Configures the maximum number of ibgp equal-cost paths for
              load sharing. Valid value is an integer in the range 1-64.
        required: false
        default: null
    networks:
        description:
            - Networks to configure. Valid value is a list of network
              prefixes to advertise. The list must be in the form of an array.
              Each entry in the array must include a prefix address and an
              optional route-map. Example: [['10.0.0.0/16', 'routemap_LA'],
              ['192.168.1.1', 'Chicago'], ['192.168.2.0/24],
              ['192.168.3.0/24', 'routemap_NYC']]
        required: false
        default: null
    next_hop_route_map:
        description:
            - Configure a route-map for valid nexthops.
        required: false
        default: null
    redistribute:
        description:
            - A list of redistribute directives. Multiple redistribute entries
              are allowed. The list must be in the form of a nested array:
              the first entry of each array defines the source-protocol to
              redistribute from; the second entry defines a route-map name.
              A route-map is highly advised but may be optional on some
              platforms, in which case it may be omitted from the array list.
              Example: [['direct', 'rm_direct'], ['lisp', 'rm_lisp']]
        required: false
        default: null
    suppress_inactive:
        description:
            - Advertises only active routes to peers.
        required: false
        choices: ['true','false', 'default']
        default: null
    table_map:
        description:
            - Apply table-map to filter routes downloaded into URIB.
        required: false
        default: null
    table_map_filter:
        description:
            - Filters routes rejected by the route-map and does not download
              them to the RIB.
        required: false
        choices: ['true','false', 'default']
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
# configure a simple asn
- nxos_bgp:
      asn=65535
      vrf=default
      state=present
      transport=cli
'''

RETURN = '''

'''
ACCEPTED = ['true','false', 'default']
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
PARAM_TO_DEFAULT_KEYMAP = {
    'maximum_paths': '1',
    'maximum_paths_ibgp': '1',
    'client_to_client': True,
    'distance_ebgp': '20',
    'distance_ibgp': '200',
    'distance_local': '220',
    'dampen_igp_metric': '600'
}
DAMPENING_PARAMS = [
    'dampening_half_time',
    'dampening_reuse_time',
    'dampening_suppress_time',
    'dampening_max_suppress_time'
]
PARAM_TO_COMMAND_KEYMAP = {
    'asn': 'router bgp',
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

        parents.append('address-family {0} {1}'.format(module.params['afi'],
                                                module.params['safi']))
        config = netcfg.get_section(parents)

        if config:
            for arg in args:
                if arg not in ['asn', 'afi', 'safi', 'vrf']:
                    existing[arg] = get_value(arg, config, module)

            existing['asn'] = existing_asn
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


def state_present(module, existing, proposed):
    commands = list()
    proposed_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, proposed)
    existing_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, existing)

    for key, value in proposed_commands.iteritems():
        if value is True:
            commands.append(key)

        elif value is False:
            commands.append('no {0}'.format(key))

        elif value == 'default':
            if key == 'vrf':
                pass

            elif key in PARAM_TO_DEFAULT_KEYMAP.keys():
                commands.append('{0} {1}'.format(key, PARAM_TO_DEFAULT_KEYMAP[key]))

            elif existing_commands.get(key):
                existing_value = existing_commands.get(key)

                if key.startswith('distance'):
                    commands.append('no distance')

                elif key in DAMPENING_PARAMS:
                    command = ('no dampening {0} {1} {2} {3}'.format(
                        existing['dampening_half_time'],
                        existing['dampening_reuse_time'],
                        existing['dampening_suppress_time'],
                        existing['dampening_max_suppress_time'],
                    ))
                    if command not in commands:
                        commands.append(command)
                else:
                    commands.append('no {0} {1}'.format(key, existing_value))
            else:
                if key.replace(' ', '_').replace('-', '_') in BOOL_PARAMS:
                    commands.append('no {0}'.format(key))
        else:
            if key == 'network':
                existing_networks = existing.get('networks')

                for inet in value:
                    if not isinstance(inet, list):
                        inet = [inet]

                    if inet not in existing_networks:
                        if len(inet) == 1:
                            command = '{0} {1}'.format(key, inet[0])
                        elif len(inet) == 2:
                            command = '{0} {1} route-map {2}'.format(key,
                                                            inet[0], inet[1])
                        commands.append(command)

            elif key == 'inject_map':
                existing_maps = existing.get('inject_map')

                for maps in value:
                    if maps not in existing_networks:
                        if len(maps) == 2:
                            command = ('inject-map {0} exist-map {1}'.format(
                                        maps[0], maps[1]))
                        elif len(inet) == 3:
                            command = ('inject-map {0} exist-map {1} '
                                       'copy-attributes'.format(maps[0],
                                                                maps[1]))
                        commands.append(command)
            else:
                command = '{0} {1}'.format(key, value)
                commands.append(command)

    asn_command = 'router bgp {0}'.format(module.params['asn'])
    if asn_command in commands:
        commands.remove(asn_command)
    commands.insert(0, asn_command)
    return commands


def fix_commands(commands, module):
    if module.params['state'] == 'present':
        commands.insert(0, 'address-family {0} {1}'.format(
                            module.params['afi'], module.params['safi']))
        if module.params['vrf'] != 'default':
            vrf_command = 'vrf {0}'.format(module.params['vrf'])

            if vrf_command not in commands:
                commands.insert(0, vrf_command)

    asn_command = 'router bgp {0}'.format(module.params['asn'])
    if asn_command in commands:
        commands.remove(asn_command)
    commands.insert(0, asn_command)

    return commands


def custom_load_config(module, temp_commands):
    commands = list()
    netcfg = get_config(module)
    parents = ['router bgp {0}'.format(module.params['asn'])]

    if module.params['vrf'] != 'default':
        parents.append('vrf {0}'.format(module.params['vrf']))

    parents.append('address-family {0} {1}'.format(module.params['afi'],
                                            module.params['safi']))

    section = netcfg.get_section(parents)
    if section:
        splitted_section = section.splitlines()
        splitted_section.append('router bgp {0}'.format(module.params['asn']))
    else:
        splitted_section = []

    stripped_section = [elem.strip() for elem in splitted_section]
    commands = [command for command in temp_commands if command not in stripped_section]
    save_config = module.params['save_config']
    result = dict(changed=False)

    if commands:
        commands = fix_commands(commands, module)

        if not module.check_mode:
            module.config(commands)
            if save_config:
                module.config.save_config()

        result['changed'] = True
        result['updates'] = commands

    return result


def main():
    argument_spec = dict(
            asn=dict(required=True, type='str'),
            vrf=dict(required=False, type='str', default='default'),
            safi=dict(required=True, type='str', choices=['unicast','multicast', 'evpn']),
            afi=dict(required=True, type='str', choices=['ipv4','ipv6', 'vpnv4', 'vpnv6', 'l2vpn']),
            additional_paths_install=dict(required=False, choices=ACCEPTED),
            additional_paths_receive=dict(required=False, choices=ACCEPTED),
            additional_paths_selection=dict(required=False, type='str'),
            additional_paths_send=dict(required=False, choices=ACCEPTED),
            advertise_l2vpn_evpn=dict(required=False, choices=['true', 'false']),
            client_to_client=dict(required=False, choices=['true', 'false']),
            dampen_igp_metric=dict(required=False, type='str'),
            dampening_state=dict(required=False, type=ACCEPTED),
            dampening_half_time=dict(required=False, type='str'),
            dampening_max_suppress_time=dict(required=False, choices='str'),
            dampening_reuse_time=dict(required=False, type='str'),
            dampening_routemap=dict(required=False, type='str'),
            dampening_suppress_time=dict(required=False, type='str'),
            default_information_originate=dict(required=False, choices=['true', 'false']),
            default_metric=dict(required=False, type='str'),
            distance_ebgp=dict(required=False, type='str'),
            distance_ibgp=dict(required=False, type='str'),
            distance_local=dict(required=False, type='str'),
            inject_map=dict(required=False, type='str'),
            maximum_paths=dict(required=False, type='str'),
            maximum_paths_ibgp=dict(required=False, type='str'),
            networks=dict(required=False, type='list'),
            next_hop_route_map=dict(required=False, type='str'),
            redistribute_direct=dict(required=False),
            redistribute_eigrp=dict(required=False),
            redistribute_hmm=dict(required=False),
            redistribute_isis=dict(required=False),
            redistribute_ospf=dict(required=False),
            redistribute_static=dict(required=False),
            redistribute_rip=dict(required=False),
            redistribute_lisp=dict(required=False),
            suppress_inactive=dict(required=False, choices=ACCEPTED),
            table_map=dict(required=False, type='str'),
            table_map_filter=dict(required=False, choices=ACCEPTED),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        required_together=[DAMPENING_PARAMS,
                                            ['distance_ibgp',
                                            'distance_ebgp',
                                            'distance_local']],
                        supports_check_mode=True)

    state = module.params['state']
    if module.params['dampening_routemap']:
        for param in DAMPENING_PARAMS:
            if module.params[param]:
                module.fail_json(msg='dampening_routemap cannot be used with'
                                     ' the {0} param'.format(param))


    args =  [
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

    if proposed_args['networks'][0] == 'default':
         proposed_args['networks'] == 'default'

    proposed = {}
    for key, value in proposed_args.iteritems():
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
        temp_commands = invoke('state_%s' % state, module, existing, proposed)

        try:
            response = custom_load_config(module, temp_commands)
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
