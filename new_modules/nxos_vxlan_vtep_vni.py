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
module: nxos_vxlan_vtep_vni
version_added: "2.2"
short_description: Creates a Virtual Network Identifier member (VNI)
description:
    - Creates a Virtual Network Identifier member (VNI) for an NVE
      overlay interface.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
notes:
    - 'default' restores params default value
options:
    interface:
        description:
            - Interface name for the VXLAN Network Virtualization Endpoint
        required: true
    vni:
        description:
            - ID of the Virtual Network Identifier.
        required: true
        default: null
    ingress_replication:
        description:
            - Specifies mechanism for host reachability advertisement.
        required: false
        choices: ['bgp', 'static', 'default']
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
- nxos_vxlan_vtep_vni:
    interface=nve1
    vni=6000
    ingress_replication=default
'''

BOOL_PARAMS = []
PARAM_TO_COMMAND_KEYMAP = {
    'interface': 'interface',
    'vni': 'member vni',
    'ingress_replication': 'ingress-replication protocol',
}
PARAM_TO_DEFAULT_KEYMAP = {}
WARNINGS = []

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


def check_interface(module, netcfg):
    config = str(netcfg)

    REGEX = re.compile(r'(?:interface nve)(?P<value>.*)$', re.M)
    value = ''
    if 'interface nve' in config:
        value = 'nve{0}'.format(REGEX.search(config).group('value'))

    return value


def get_existing(module, args):
    existing = {}
    netcfg = get_config(module)

    interface_exist = check_interface(module, netcfg)
    if interface_exist:
        parents = ['interface {0}'.format(interface_exist)]
        parents.append('member vni {0}'.format(module.params['vni']))
        config = netcfg.get_section(parents)

        if config:
            for arg in args:
                if arg != 'interface':
                    existing[arg] = get_value(arg, config, module)
            existing['interface'] = interface_exist

    return existing, interface_exist


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
                    commands.append('no {0}'.format(key.lower()))
        else:
            command = '{0} {1}'.format(key, value.lower())
            commands.append(command)

    if commands:
        vni_command = 'member vni {0}'.format(module.params['vni'])
        parents = ['interface {0}'.format(module.params['interface'])]
        if vni_command in commands:
            commands.remove(vni_command)
            parents.append(vni_command)

        candidate.add(commands, parents=parents)


def state_absent(module, existing, proposed, candidate):
    commands = ['no member vni {0}'.format(module.params['vni'])]
    parents = ['interface {0}'.format(module.params['interface'])]
    candidate.add(commands, parents=parents)


def main():
    argument_spec = dict(
            interface=dict(required=True, type='str'),
            vni=dict(required=True, type='str'),
            ingress_replication=dict(required=False, type='str',
                                     choices=['bgp', 'static', 'default']),
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
            'vni',
            'ingress_replication',
        ]

    existing, interface_exist = invoke('get_existing', module, args)
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
    if state == 'present' or (state == 'absent' and existing):
        if not interface_exist:
            WARNINGS.append("The proposed NVE interface does not exist. "
                            "Use nxos_interface to create it first.")
        elif interface_exist != module.params['interface']:
            module.fail_json(msg='Only 1 NVE interface is allowed on '
                                 'the switch.')
        elif (existing and state == 'absent' and
                existing['vni'] != module.params['vni']):
                module.fail_json(msg="ERROR: VNI delete failed: Could not find"
                                     " vni node for {0}".format(
                                     module.params['vni']),
                                     existing_vni=existing['vni'])
        else:
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
        end_state, interface_exist = invoke('get_existing', module, args)
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
