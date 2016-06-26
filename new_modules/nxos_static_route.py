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
module: nxos_static_route
version_added: "2.2"
short_description: Manages static route configuration
description:
    - Manages static route configuration
author: Gabriele Gerbino (@GGabriele)
notes:
    - If no vrf is supplied, vrf is set to default
    - If state=absent, the route will be removed, regardless of the non-required parameters.
options:
    prefix:
        description:
            - Destination prefix of static route
        required: true
    next_hop:
        description:
            - Next hop address or interface of static route.
              If interface, it must be the fully-qualified interface name.
        required: true
    vrf:
        description:
            - VRF for static route
        required: false
        default: default
    tag:
        description:
            - Route tag value (numeric).
        required: false
        default: null
    route_name:
        description:
            - Name of the route. Used with the name parameter on the CLI.
        required: false
        default: null
    pref:
        description:
            - Preference or administrative difference of route (range 1-255)
        required: false
        default: null
    state:
        description:
            - Manage the state of the resource
        required: true
        choices: ['present','absent']
    m_facts:
        description:
            - Used to print module facts
        required: false
        default: false
        choices: ['true','false']
'''

import re
import collections


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def state_present(module, candidate, prefix):
    commands = list()
    invoke('set_route', module, commands, prefix)
    if commands:
        if module.params['vrf'] == 'default':
            candidate.add(commands, parents=[])
        else:
            candidate.add(commands, parents=['vrf context {0}'.format(module.params['vrf'])])


def state_absent(module, candidate, prefix):
    netcfg = get_config(module)
    commands = list()
    parents = 'vrf context {0}'.format(module.params['vrf'])
    invoke('set_route', module, commands, prefix)
    if module.params['vrf'] == 'default':
        config = netcfg.get_section(commands[0])
        if config:
            invoke('remove_route', module, commands, config, prefix)
            candidate.add(commands, parents=[])
    else:
        config = netcfg.get_section(parents)
        splitted_config = config.split('\n')
        splitted_config = map(str.strip, splitted_config)
        if commands[0] in splitted_config:
            invoke('remove_route', module, commands, config, prefix)
            candidate.add(commands, parents=[parents])


def fix_prefix_to_regex(prefix):
    prefix = prefix.split('.')
    prefix = '\.'.join(prefix)
    prefix = prefix.split('/')
    prefix = '\/'.join(prefix)

    return prefix


def get_existing(module, prefix, warnings):
    key_map = ['tag', 'pref', 'route_name', 'next_hop']
    netcfg = get_config(module)
    parents = 'vrf context {0}'.format(module.params['vrf'])
    prefix_to_regex = fix_prefix_to_regex(prefix)

    route_regex = '.*ip\sroute\s{0}\s(?P<next_hop>\S+)(\sname\s(?P<route_name>\S+))?(\stag\s(?P<tag>\d+))?(\s(?P<pref>\d+)).*'.format(prefix_to_regex)

    if module.params['vrf'] == 'default':
        config = str(netcfg)
    else:
        config = netcfg.get_section(parents)
    try:
        match_route = re.match(route_regex, config, re.DOTALL)
        group_route = match_route.groupdict()

        for key in key_map:
            if key not in group_route.keys():
                group_route['key'] = None
        group_route['prefix'] = prefix
    except (AttributeError, TypeError):
        group_route = {}
        if module.params['state'] == 'present':
            msg = ("VRF {0} doesn't exist.".format(module.params['vrf']))
            warnings.append(msg)

    return group_route


def remove_route(module, commands, config, prefix):
    commands.append('no ip route {0} {1}'.format(prefix, module.params['next_hop']))


def set_route(module, commands, prefix):
    route_cmd = 'ip route {0} {1}'.format(prefix, module.params['next_hop'])

    if module.params['route_name']:
        route_cmd += ' name {0}'.format(module.params['route_name'])
    if module.params['tag']:
        route_cmd += ' tag {0}'.format(module.params['tag'])
    if module.params['pref']:
        route_cmd += ' {0}'.format(module.params['pref'])
    commands.append(route_cmd)


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

    if len(octects) > 4:
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
        normalized_prefix = prefix + '/' + str(32)

    return normalized_prefix


def main():
    argument_spec = dict(
        prefix=dict(required=True, type='str'),
        next_hop=dict(required=True, type='str'),
        vrf=dict(type='str', default='default'),
        tag=dict(type='str'),
        route_name=dict(type='str'),
        pref=dict(type='str'),
        m_facts=dict(required=False, default=False, type='bool'),
        state=dict(choices=['absent', 'present'],
                   default='present'),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    m_facts = module.params['m_facts']
    state = module.params['state']

    result = dict(changed=False)
    warnings = list()
    prefix = invoke('normalize_prefix', module, module.params['prefix'])

    existing = invoke('get_existing', module, prefix, warnings)
    end_state = existing

    args = ['route_name', 'vrf', 'pref', 'tag', 'next_hop', 'prefix']
    proposed = dict((k, v) for k, v in module.params.iteritems() if v is not None and k in args)

    if state == 'present' or (state == 'absent' and existing):
        candidate = NetworkConfig(indent=3)
        invoke('state_%s' % state, module, candidate, prefix)

        try:
            response = load_config(module, candidate)
            result.update(response)
        except NetworkError:
            exc = get_exception()
            module.fail_json(msg=str(exc))
    else:
        result['updates'] = []

    result['warnings'] = warnings
    result['connected'] = module.connected

    if module.params['m_facts']:
        end_state = invoke('get_existing', module, prefix, warnings)
        result['end_state'] = end_state
        result['existing'] = existing
        result['proposed'] = proposed

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *


if __name__ == '__main__':
    main()
