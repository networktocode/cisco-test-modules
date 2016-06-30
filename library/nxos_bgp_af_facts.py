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


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
