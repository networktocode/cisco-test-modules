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
module: nxos_vxlan_vlan
version_added: "2.2"
short_description: Manages the VXLAN VLAN to VNI mappings.
description:
    - Manages the VXLAN VLAN to VNI mappings.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - a VNI equals to 0 means no VNI mapping at all
    - state 'present' create a proposed VLAN if this doens't exist yet.
      Anyway, we highly recommend to split the workflow into two tasks, one
      to create the VLAN and one to map it to a VNI.
options:
    vlan:
        description:
            - The VLAN ID that is associated with this mapping.
        required: true
    vni:
        description:
            - The VNI associate with the VLAN ID mapping.
        required: false
        default: null
    m_facts:
        description:
            - Used to print module facts
        required: false
        default: false
        choices: ['true','false']
    state:
        description:
            - Determines whether the config should be present or not on the device.
        required: false
        default: present
        choices: ['present','absent']
'''
EXAMPLES = '''
- nxos_vxlan_vlan:
    vlan: "100"
    vni: "4096"
    state: present
'''

PARAM_TO_COMMAND_KEYMAP = {
    'vni': 'vn-segment',
    'vlan': 'vlan'
}
WARNINGS = []


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_value(arg, config, module):
    REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
    value = ''
    if PARAM_TO_COMMAND_KEYMAP[arg] in config:
        value = REGEX.search(config).group('value').strip()

    return value


def get_existing(module, args):
    existing = {}
    netcfg = get_config(module)

    parents = ['vlan {0}'.format(module.params['vlan'])]
    config = netcfg.get_section(parents)

    if config:
        existing['vni'] = get_value('vni', config, module)
        existing['vlan'] = module.params['vlan']
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
        if key != 'vlan':
            command = '{0} {1}'.format(key, value)
            commands.append(command)
    if commands:
        if existing:
            if existing['vni'] != proposed['vni'] and existing['vni'] != '0':
                commands.insert(0, 'no vn-segment')
        parents = ['vlan {0}'.format(module.params['vlan'])]
        candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    if existing['vni'] == proposed['vni']:
        commands = ['no vn-segment']
        parents = ['vlan {0}'.format(module.params['vlan'])]
        candidate.add(commands, parents=parents)


def main():
    argument_spec = dict(
            vlan=dict(required=True, type='str'),
            vni=dict(required=True, type='str'),
            m_facts=dict(required=False, default=False, type='bool'),
            state=dict(choices=['present', 'absent'], default='present',
                       required=False),
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    state = module.params['state']
    args =  ['vlan', 'vni',]

    existing = invoke('get_existing', module, args)
    end_state = existing
    proposed = dict((k, v) for k, v in module.params.iteritems()
                    if v is not None and k in args)

    result = {}
    if (state == 'present' or (state == 'absent' and
                            existing.get('vni') != '0')):
        if not existing:
            WARNINGS.append('VLAN {0} did not exist. The task just '
                            'created it'.format(module.params['vlan']))

        elif existing:
            if (state == 'present' and
                module.params['vni'] != existing['vni'] and
                existing['vni'] != '0'):
                WARNINGS.append('VNI {0} was automatically unmapped from this'
                                ' VLAN. It is highly recommended to use a task'
                                ' with state=absent to explicitly unconfigure'
                                ' a VNI to VLAN mapping.'.format(
                                                            existing['vni']))

        if state == 'absent' and existing.get('vni') != proposed.get('vni'):
            module.fail_json(msg='A different VNI is mapped to this '
                                 'VLAN.', existing_vni=existing['vni'],
                                 proposed_vni=proposed['vni'])

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
        result['proposed'] = proposed

    if WARNINGS:
        result['warnings'] = WARNINGS

    module.exit_json(**result)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
