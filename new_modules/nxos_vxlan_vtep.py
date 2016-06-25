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
module: nxos_vxlan_vtep
version_added: "2.2"
short_description: Manages VXLAN Network Virtualization Endpoint (NVE)
description:
    - Manages VXLAN Network Virtualization Endpoint (NVE) overlay interface
      that terminates VXLAN tunnels.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - The module is used to manage NVE properties, not to create NVE
      interfaces. Use nxos_interface if you wish to do so.
    - State 'absent' removes the interface
    - 'default' restores params default value
options:
    interface:
        description:
            - Interface name for the VXLAN Network Virtualization Endpoint
        required: true
    description:
        description:
            - Description of the NVE interface.
        required: false
        default: null
    host_reachability:
        description:
            - Specify mechanism for host reachability advertisement.
        required: false
        choices: ['true', 'false', 'default']
        default: null
    shutdown:
        description:
            - Administratively shutdown the NVE interface.
        required: false
        choices: ['true','false', 'default']
        default: false
    source_interface:
        description:
            - Specify the loopback interface whose IP address should be
              used for the NVE interface.
        required: false
        default: null
    source_interface_hold_down_time:
        description:
            - Suppresses advertisement of the NVE loopback address until
              the overlay has converged.
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
- nxos_vxlan_vtep:
    interface=nve1
    description=default
    host_reachability=default
    source_interface=Loopback0
    source_interface_hold_down_time=30
    shutdown=default
'''

ACCEPTED = ['true','false', 'default']
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
PARAM_TO_DEFAULT_KEYMAP = {
    'description': False,
    'shutdown': True,
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
        NO_DESC_REGEX = re.compile(r'\s+{0}\s*$'.format('no description'), re.M)
        value = ''
        if arg == 'description':
            if NO_DESC_REGEX.search(config):
                value = ''
            elif PARAM_TO_COMMAND_KEYMAP[arg] in config:
                value = REGEX.search(config).group('value').strip()
    return value


def get_existing(module, args):
    existing = {}
    netcfg = get_config(module)

    parents = ['interface {0}'.format(module.params['interface'])]
    config = netcfg.get_section(parents)

    if config:
        for arg in args:
            existing[arg] = get_value(arg, config, module)

        existing['interface'] = module.params['interface']
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
        parents = ['interface {0}'.format(module.params['interface'])]
        candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    commands = ['no interface {0}'.format(module.params['interface'])]
    candidate.add(commands, parents=[])


def main():
    argument_spec = dict(
            interface=dict(required=True, type='str'),
            description=dict(required=False, type='str'),
            host_reachability=dict(required=False, type='str', choices=ACCEPTED),
            shutdown=dict(required=False, type='str', choices=ACCEPTED),
            source_interface=dict(required=False, type='str'),
            source_interface_hold_down_time=dict(required=False, type='str'),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']

    args =  [
            'interface',
            'description',
            'host_reachability',
            'shutdown',
            'source_interface',
            'source_interface_hold_down_time'
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
    if existing:
        candidate = NetworkConfig(indent=3)
        invoke('state_%s' % state, module, existing, proposed, candidate)

        try:
            response = load_config(module, candidate)
            result.update(response)
        except NetworkError:
            exc = get_exception()
            module.fail_json(msg=str(exc))
    else:
        if module.params['state'] == 'present':
            module.fail_json(msg='The proposed NVE interface does not exist '
                                 'yet. Use nxos_interface to create it.',
                                 interface=module.params['interface'])
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
