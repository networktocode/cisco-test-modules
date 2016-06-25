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

module: nxos_static_route_facts
version_added: "2.2"
short_description: Retrieve static route configuration
description:
    - Retrieve static route configuration
author: Gabriele Gerbino (@GGabriele)
notes:
    - If no vrf is supplied, all the static routes are returned
options:
    prefix:
        description:
            - Destination prefix of static route
        required: true
    vrf:
        description:
            - VRF for static route
        required: false
        default: default
'''

import re
import collections
import json


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def fix_prefix_to_regex(prefix):
    prefix = prefix.split('.')
    prefix = '\.'.join(prefix)
    prefix = prefix.split('/')
    prefix = '\/'.join(prefix)

    return prefix


def match_static_route(config, route_regex):
    key_map = ['tag', 'pref', 'route_name', 'next_hop']
    try:
        match_route = re.match(route_regex, config, re.DOTALL)
        group_route = match_route.groupdict()

        for key in key_map:
            if key not in group_route.keys():
                group_route['key'] = None
    except (AttributeError, TypeError):
        group_route = {}

    return group_route


def get_vrf_list(module):
    vrf_list = []
    cmd = 'show vrf'
    response = module.cli(cmd, output='json')

    try:
        vrf_table_list = response[0]['TABLE_vrf']['ROW_vrf']
        for member in vrf_table_list:
            vrf_list.append(member['vrf_name'])
    except KeyError, IndexError:
        vrf_list = []

    return vrf_list


def parse_routes(module, vrf, netcfg):
    route_list = []
    route_all_vrf_regex = ('\s+ip\sroute\s(?P<prefix>\S+)\s(?P<next_hop>\S+)'
                           '(\sname\s(?P<route_name>\S+))?(\stag\s(?P<tag>\d+)'
                           ')?(\s(?P<pref>\d+))?')
    route_default_vrf_regex = ('^ip\sroute\s(?P<prefix>\S+)\s(?P<next_hop>\S+)'
                               '(\sname\s(?P<route_name>\S+))?'
                               '(\stag\s(?P<tag>\d+))?(\s(?P<pref>\d+))?')

    if module.params['prefix']:
        prefix = invoke('normalize_prefix', module, module.params['prefix'])
        prefix_to_regex = fix_prefix_to_regex(prefix)
        route_prefix_regex = ('.*ip\sroute\s{0}\s(?P<next_hop>\S+)'
                              '(\sname\s(?P<route_name>\S+))?(\stag\s(?P<tag>\d+))'
                              '?(\s(?P<pref>\d+)).*'.format(prefix_to_regex))

    if vrf == 'default':
        config = str(netcfg)
        if module.params['prefix']:
            route_regex = route_prefix_regex
        else:
            route_regex = route_default_vrf_regex
    else:
        parents = 'vrf context {0}'.format(vrf)
        config = netcfg.get_section(parents)
        if module.params['prefix']:
            route_regex = route_prefix_regex
        else:
            route_regex = route_all_vrf_regex

    if config:
        splitted_config = config.split('\n')
        for line in splitted_config:
            group_route = match_static_route(line, route_regex)

            if group_route:
                group_route['vrf'] = vrf
                route_list.append(group_route)
    return route_list


def get_existing_routes(module, vrf, warnings):
    route_list = []
    vrf_list = get_vrf_list(module)
    netcfg = get_config(module)

    if vrf:
        parsed_route = parse_routes(module, vrf, netcfg)
        route_list.extend(parsed_route)
    else:
        for each_vrf in vrf_list:
            parsed_route = parse_routes(module, each_vrf, netcfg)
            route_list.extend(parsed_route)

    return route_list


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

    if len(octects) != 4:
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
        splitted_prefix = prefix.split('.')
        if len(splitted_prefix) != 4:
            module.fail_json(msg='Incorrect address format.', address=prefix)
        else:
            normalized_prefix = prefix + '/' + str(32)

    return normalized_prefix


def main():
    argument_spec = dict(
        prefix=dict(required=False, type='str'),
        vrf=dict(type='str', required=False,),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    vrf = module.params['vrf']

    result = dict(changed=False)
    warnings = list()
    route_facts = dict(nxos_static_routes=invoke('get_existing_routes', module, vrf, warnings))

    """result['static_route_facts'] = route_facts
    result['warnings'] = warnings
    result['connected'] = module.connected"""

    module.exit_json(ansible_facts=route_facts)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *


if __name__ == '__main__':
    main()
