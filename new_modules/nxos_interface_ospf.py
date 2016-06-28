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
module: nxos_interface_ospf
version_added: "2.2"
short_description: Manages configuration of an OSPF interface instance.
description:
    - Manages configuration of an OSPF interface instance.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - 'default' restores params default value
    - State absent remove the whole OSPF interface configuration
options:
    interface:
        description:
            - Name of this cisco_interface resource. Valid value is a string.
        required: true
    ospf:
        description:
            - Name of the ospf instance.
        required: true
    area:
        description:
            - Ospf area associated with this cisco_interface_ospf instance.
              Valid values are a string, formatted as an IP address
              (i.e. "0.0.0.0") or as an integer.
        required: true
    cost:
        description:
            - The cost associated with this cisco_interface_ospf instance.
        required: false
        default: null
    m_facts:
        description:
            - Used to print module facts
        required: false
        default: false
        choices: ['true','false']
'''
EXAMPLES = '''
- interface=ethernet1/32
    ospf=1
    area=1
    cost=default
'''

PARAM_TO_COMMAND_KEYMAP = {
    'cost': 'ip ospf cost',
    'ospf': 'ip router ospf',
    'area': 'ip router ospf'
}
PARAM_TO_DEFAULT_KEYMAP = {}


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_custom_value(arg, config, module):
    if arg == 'ospf':
        REGEX = re.compile(r'(?:ip router ospf\s)(?P<value>.*)$', re.M)
        value = ''
        if 'ip router ospf' in config:
            parsed = REGEX.search(config).group('value').split()
            value = parsed[0]

    elif arg == 'area':
        REGEX = re.compile(r'(?:ip router ospf\s)(?P<value>.*)$', re.M)
        value = ''
        if 'ip router ospf' in config:
            parsed = REGEX.search(config).group('value').split()
            value = parsed[2]
    return value



def get_value(arg, config, module):
    custom = [
        'ospf',
        'area'
    ]

    if arg in custom:
        value = get_custom_value(arg, config, module)
    else:
        REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = ''
        if PARAM_TO_COMMAND_KEYMAP[arg] in config:
            value = REGEX.search(config).group('value')
    return value


def get_existing(module, args):
    existing = {}
    netcfg = get_config(module)
    parents = ['interface {0}'.format(module.params['interface'].capitalize())]

    config = netcfg.get_section(parents)

    if 'ospf' in config:
        for arg in args:
            if arg not in ['interface']:
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
            if key == 'ip router ospf':
                command = '{0} {1} area {2}'.format(key, proposed['ospf'],
                                                    proposed['area'])
                if command not in commands:
                    commands.append(command)
            else:
                command = '{0} {1}'.format(key, value.lower())
                commands.append(command)

    if commands:
        parents = ['interface {0}'.format(module.params['interface'].capitalize())]

        candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    commands = []
    parents = ['interface {0}'.format(module.params['interface'].capitalize())]
    existing_commands = apply_key_map(PARAM_TO_COMMAND_KEYMAP, existing)
    existing_commands['ip router ospf'] = '{0} area {1}'.format(
                                        proposed['ospf'], proposed['area'])
    for key, value in existing_commands.iteritems():
        if value:
            existing_value = existing_commands.get(key)
            commands.append('no {0} {1}'.format(key, existing_value))

    candidate.add(commands, parents=parents)


def normalize_area(area, module):
    try:
        area = int(area)
        area = '0.0.0.{0}'.format(area)
    except ValueError:
        splitted_area = area.split('.')
        if len(splitted_area) != 4:
            module.fail_json(msg='Incorrect Area ID format', area=area)
    return area


def main():
    argument_spec = dict(
            interface=dict(required=True, type='str'),
            ospf=dict(required=True, type='str'),
            area=dict(required=True, type='str'),
            cost=dict(required=False, type='str'),
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
            'ospf',
            'area',
            'cost'
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
                    value = 'default'
            if existing.get(key) or (not existing.get(key) and value):
                proposed[key] = value

    proposed['area'] = normalize_area(proposed['area'], module)
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
