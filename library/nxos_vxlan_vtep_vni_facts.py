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
module: nxos_vxlan_vtep_vni_facts
version_added: "2.2"
short_description: Retrieve Virtual Network Identifier (VNI) configuration
description:
    - Retrieve Virtual Network Identifier (VNI) configuration
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
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
'''
EXAMPLES = '''
- nxos_vxlan_vtep_vni_facts:
    interface: nve1
    vni: 6000
'''

BOOL_PARAMS = []
PARAM_TO_COMMAND_KEYMAP = {
    'interface': 'interface',
    'vni': 'member vni',
    'ingress_replication': 'ingress-replication protocol',
}
ARGS =  [
        'interface',
        'vni',
        'ingress_replication',
    ]
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


def get_existing(module):
    existing = {}
    netcfg = get_config(module)

    interface_exist = check_interface(module, netcfg)
    if interface_exist:
        parents = ['interface {0}'.format(interface_exist)]
        parents.append('member vni {0}'.format(module.params['vni']))
        config = netcfg.get_section(parents)

        if config:
            for arg in ARGS:
                if arg != 'interface':
                    existing[arg] = get_value(arg, config, module)
            existing['interface'] = interface_exist

    return existing, interface_exist


def main():
    argument_spec = dict(
            interface=dict(required=True, type='str'),
            vni=dict(required=True, type='str')
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing, interface_exist = invoke('get_existing', module)
    if not interface_exist:
        WARNINGS.append("The proposed NVE interface does not exist.")
    vxlan_vtep_vni_facts = dict(vxlan_vtep_vni_facts=existing)
    module.exit_json(ansible_facts=vxlan_vtep_vni_facts,
                     changed=False,
                     warnings=WARNINGS)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
