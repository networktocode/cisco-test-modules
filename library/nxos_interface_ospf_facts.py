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
module: nxos_interface_ospf_facts
version_added: "2.2"
short_description: Retrieve configuration of an OSPF interface instance.
description:
    - Retrieve configuration of an OSPF interface instance.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
options:
    interface:
        description:
            - Name of this cisco_interface resource. Valid value is a string.
        required: true
'''
EXAMPLES = '''
- nxos_interface_ospf_facts:
    interface=ethernet1/32
'''

PARAM_TO_COMMAND_KEYMAP = {
    'cost': 'ip ospf cost',
    'ospf': 'ip router ospf',
    'area': 'ip router ospf'
}
ARGS =  [
        'interface',
        'ospf',
        'area',
        'cost'
    ]


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


def get_existing(module):
    existing = {}
    netcfg = get_config(module)
    parents = ['interface {0}'.format(module.params['interface'].capitalize())]

    config = netcfg.get_section(parents)

    if 'ospf' in config:
        for arg in ARGS:
            if arg not in ['interface']:
                existing[arg] = get_value(arg, config, module)
        existing['interface'] = module.params['interface']

    return existing


def main():
    argument_spec = dict(
            interface=dict(required=True, type='str')
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    interface_ospf_facts = dict(interface_ospf_facts=existing)
    module.exit_json(ansible_facts=interface_ospf_facts,
                     changed=False)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
