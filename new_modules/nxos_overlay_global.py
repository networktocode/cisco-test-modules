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
module: nxos_overlay_global
version_added: "2.2"
short_description: Handles the detection of duplicate IP or MAC addresses
description:
    - Handles the detection of duplicate IP or MAC addresses based on the
      number of moves in a given time-interval (seconds). Also configures
      anycast gateway MAC of the switch.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - 'default' restores params default value
    - Supported MAC address format are E.E.E, EE-EE-EE-EE-EE-EE,
      EE:EE:EE:EE:EE:EE and EEEE.EEEE.EEEE
options:
    anycast_gateway_mac:
        description:
            - Anycast gateway mac of the switch.
        required: true
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
- nxos_overlay_global:
    anycast_gateway_mac="b.b.b"
'''
PARAM_TO_COMMAND_KEYMAP = {
    'anycast_gateway_mac': 'fabric forwarding anycast-gateway-mac',
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


def get_existing(module, args):
    existing = {}
    config = str(get_config(module))

    for arg in args:
        existing[arg] = get_value(arg, config, module)
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


def get_commands(module, existing, proposed, candidate):
    commands = list()
    proposed_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, proposed)
    existing_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, existing)

    for key, value in proposed_commands.iteritems():
        if value == 'default':
            existing_value = existing_commands.get(key)
            if existing_value:
                commands.append('no {0} {1}'.format(key, existing_value))
        else:
            if 'anycast-gateway-mac' in key:
                value = normalize_mac(value, module)
            command = '{0} {1}'.format(key, value)
            commands.append(command)

    if commands:
        candidate.add(commands, parents=[])


def normalize_mac(proposed_mac, module):
    try:
        if '-' in proposed_mac:
            splitted_mac = proposed_mac.split('-')
            if len(splitted_mac) != 6:
                raise ValueError

            for octect in splitted_mac:
                if len(octect) != 2:
                    raise ValueError

        elif '.' in proposed_mac:
            splitted_mac = []
            splitted_dot_mac = proposed_mac.split('.')
            if len(splitted_dot_mac) != 3:
                raise ValueError

            for octect in splitted_dot_mac:
                if len(octect) > 4:
                    raise ValueError
                else:
                    octect_len = len(octect)
                    padding = 4 - octect_len
                    splitted_mac.append(octect.zfill(padding+1))

        elif ':' in proposed_mac:
            splitted_mac = proposed_mac.split(':')
            if len(splitted_mac) != 6:
                raise ValueError

            for octect in splitted_mac:
                if len(octect) != 2:
                    raise ValueError
        else:
            raise ValueError
    except ValueError:
        module.fail_json(msg='Invalid MAC address format',
                             proposed_mac=proposed_mac)

    joined_mac = ''.join(splitted_mac)
    mac = [joined_mac[i:i+4] for i in range(0, len(joined_mac), 4)]
    return '.'.join(mac).upper()


def main():
    argument_spec = dict(
            anycast_gateway_mac=dict(required=True, type='str'),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']
    args =  [
            'anycast_gateway_mac'
        ]

    existing = invoke('get_existing', module, args)
    end_state = existing
    proposed = dict((k, v) for k, v in module.params.iteritems()
                    if v is not None and k in args)

    result = {}
    candidate = NetworkConfig(indent=3)
    invoke('get_commands', module, existing, proposed, candidate)

    try:
        response = load_config(module, candidate)
        result.update(response)
    except NetworkError:
        exc = get_exception()
        module.fail_json(msg=str(exc))

    result['connected'] = module.connected
    if module.params['m_facts']:
        end_state = invoke('get_existing', module, args)
        result['end_state'] = end_state
        result['existing'] = existing
        result['proposed'] = proposed

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
