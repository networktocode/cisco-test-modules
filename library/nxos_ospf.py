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
module: nxos_ospf
version_added: "2.2"
short_description: Manages configuration of an ospf instance.
description:
    - Manages configuration of an ospf instance.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
options:
    ospf:
        description:
            - Name of the ospf instance.
        required: true
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
- nxos_ospf:
    ospf=ntc
'''


PARAM_TO_COMMAND_KEYMAP = {
    'ospf': 'router ospf'
}


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_value(config, module):
    splitted_config = config.splitlines()
    value_list = []
    REGEX = '^router ospf\s(?P<ospf>\S+).*'
    for line in splitted_config:
        value = ''
        if 'router ospf' in line:
            try:
                match_ospf = re.match(REGEX, line, re.DOTALL)
                ospf_group = match_ospf.groupdict()
                value = ospf_group['ospf']
            except AttributeError:
                value = ''
            if value:
                value_list.append(value)

    return value_list


def get_existing(module):
    existing = {}
    config = str(get_config(module))

    value = get_value(config, module)
    if value:
        existing['ospf'] = value
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


def state_present(module, proposed, candidate):
    commands = ['router ospf {0}'.format(proposed['ospf'])]
    candidate.add(commands, parents=[])


def state_absent(module, proposed, candidate):
    commands = ['no router ospf {0}'.format(proposed['ospf'])]
    candidate.add(commands, parents=[])


def main():
    argument_spec = dict(
            ospf=dict(required=True, type='str'),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']
    ospf = str(module.params['ospf'])

    existing = invoke('get_existing', module)
    end_state = existing
    proposed = dict(ospf=ospf)

    if not existing:
        existing_list = []
    else:
        existing_list = existing['ospf']

    result = {}
    if (state == 'present' or (state == 'absent' and ospf in existing_list)):
        candidate = NetworkConfig(indent=3)
        invoke('state_%s' % state, module, proposed, candidate)

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
        end_state = invoke('get_existing', module)
        result['end_state'] = end_state
        result['existing'] = existing
        result['proposed'] = proposed

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
