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
module: nxos_ospf_vrf_facts
version_added: "2.2"
short_description: Retrieve VRF configuration for an OSPF router.
description:
    - Retrieve VRF configuration for an OSPF router.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
options:
    vrf:
        description:
            - Name of the resource instance. Valid value is a string.
              The name 'default' is a valid VRF representing the global ospf.
        required: false
        default: default
    ospf:
        description:
            - Name of the ospf instance.
        required: true
        default: null
'''
EXAMPLES = '''
- nxos_ospf_vrf_facts:
    ospf: 1
    vrf: test
'''

PARAM_TO_COMMAND_KEYMAP = {
    'router_id': 'router-id',
}
ARGS =  [
        'vrf',
        'ospf',
        'router_id',
    ]


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


def get_existing(module):
    existing = {}
    netcfg = get_config(module)
    parents = ['router ospf {0}'.format(module.params['ospf'])]

    if module.params['vrf'] != 'default':
        parents.append('vrf {0}'.format(module.params['vrf']))

    config = netcfg.get_section(parents)

    if config:
        if module.params['vrf'] == 'default':
            splitted_config = config.splitlines()
            vrf_index = False
            for index in range(0, len(splitted_config) - 1):
                if 'vrf' in splitted_config[index].strip():
                        vrf_index = index
                        break
            if vrf_index:
                config = '\n'.join(splitted_config[0:vrf_index])

        for arg in ARGS:
            if arg not in ['ospf', 'vrf']:
                existing[arg] = get_value(arg, config, module)

        existing['vrf'] = module.params['vrf']
        existing['ospf'] = module.params['ospf']
    return existing


def main():
    argument_spec = dict(
            vrf=dict(required=False, type='str', default='default'),
            ospf=dict(required=True, type='str')
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    ospf_vrf_facts = dict(ospf_vrf_facts=existing)
    module.exit_json(ansible_facts=ospf_vrf_facts,
                     changed=False)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
