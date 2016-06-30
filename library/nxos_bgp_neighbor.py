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
module: nxos_bgp_neighbor
version_added: "2.2"
short_description: Manages BGP neighbors configurations
description:
    - Manages BGP neighbors configurations on NX-OS switches
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - State 'absent' removes the whole BGP neighbor configuration
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
    description:
        description:
            - Description of the neighbor.
        required: false
        default: null
    local_as:
        description:
            - Specify the local-as number for the eBGP neighbor.
              Valid values are String or Integer in ASPLAIN or ASDOT notation,
              or 'default', which means not to configure it.
        required: false
        default: null
    remote_as:
        description:
            - Specify Autonomous System Number of the neighbor.
              Valid values are String or Integer in ASPLAIN or ASDOT notation,
              or 'default', which means not to configure it.
        required: false
        default: null
    shutdown:
        description:
            - Configure to administratively shutdown this neighbor.
        required: false
        choices: ['true','false']
        default: null
    update_source:
        description:
            - Specify source interface of BGP session and updates.
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
# create a new neighbor
- nxos_bgp_neighbor:
    asn: 65535
    neighbor: 3.3.3.3
    local_as: 20
    remote_as: 30
    description: "just a description"
    update_source: Ethernet1/3
    shutdown: default
    state: present
'''

WARNINGS = []
BOOL_PARAMS = [
    'shutdown'
]
PARAM_TO_COMMAND_KEYMAP = {
    'asn': 'router bgp',
    'description': 'description',
    'local_as': 'local-as',
    'neighbor': 'neighbor',
    'remote_as': 'remote-as',
    'shutdown': 'shutdown',
    'update_source': 'update-source',
    'vrf': 'vrf'
}
PARAM_TO_DEFAULT_KEYMAP = {
    'shutdown': False
}

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
        config = netcfg.get_section(parents)

        if config:
            for arg in args:
                if arg not in ['asn', 'vrf', 'neighbor']:
                    existing[arg] = get_value(arg, config, module)

            existing['asn'] = existing_asn
            existing['neighbor'] = module.params['neighbor']
            existing['vrf'] = module.params['vrf']
    else:
        WARNINGS.append("The BGP process didn't exist but the task"
                        " just created it.")

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
                    commands.append('no {0}'.format(key))
        else:
            command = '{0} {1}'.format(key, value)
            commands.append(command)

    if commands:
        parents = ["router bgp {0}".format(module.params['asn'])]
        if module.params['vrf'] != 'default':
            parents.append('vrf {0}'.format(module.params['vrf']))

        if len(commands) == 1:
            candidate.add(commands, parents=parents)

        elif len(commands) > 1:
            neighbor_command = 'neighbor {0}'.format(module.params['neighbor'])
            if neighbor_command in commands:
                commands.remove(neighbor_command)
            parents.append('neighbor {0}'.format(module.params['neighbor']))

        # make sure that local-as is the last command in the list.
        local_as_command = 'local-as {0}'.format(module.params['local_as'])
        if local_as_command in commands:
            commands.remove(local_as_command)
            commands.append(local_as_command)
        candidate.add(commands, parents=parents)

def state_absent(module, existing, proposed, candidate):
    commands = []
    parents = ["router bgp {0}".format(module.params['asn'])]
    if module.params['vrf'] != 'default':
        parents.append('vrf {0}'.format(module.params['vrf']))

    commands.append('no neighbor {0}'.format(module.params['neighbor']))

    candidate.add(commands, parents=parents)


def main():
    argument_spec = dict(
            asn=dict(required=True, type='str'),
            vrf=dict(required=False, type='str', default='default'),
            neighbor=dict(required=True, type='str'),
            description=dict(required=False, type='str'),
            local_as=dict(required=False, type='str'),
            remote_as=dict(required=False, type='str'),
            shutdown=dict(required=False, type='str'),
            update_source=dict(required=False, type='str'),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']

    args =  [
            'asn',
            'description',
            'local_as',
            'neighbor',
            'remote_as',
            'shutdown',
            'update_source',
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
        if key not in ['asn', 'vrf']:
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
