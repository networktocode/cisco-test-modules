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
short_description: Retrieve BGP neighbors configuration
description:
    - Retrieve BGP neighbors configurations on NX-OS switches
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
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
'''
EXAMPLES = '''
# create a new neighbor
- nxos_bgp_neighbor_facts:
    asn=65535
    neighbor=2.2.2.2
    vrf=test
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
ARGS =  [
    'asn',
    'description',
    'local_as',
    'neighbor',
    'remote_as',
    'shutdown',
    'update_source',
    'vrf'
    ]


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


def get_existing(module):
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
            for arg in ARGS:
                if arg not in ['asn', 'vrf', 'neighbor']:
                    existing[arg] = get_value(arg, config, module)

            existing['asn'] = existing_asn
            existing['neighbor'] = module.params['neighbor']
            existing['vrf'] = module.params['vrf']

    return existing


def main():
    argument_spec = dict(
            asn=dict(required=True, type='str'),
            vrf=dict(required=False, type='str', default='default'),
            neighbor=dict(required=True, type='str')
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)
    if existing.get('asn'):
        if existing.get('asn') != module.params['asn']:
            WARNINGS.append('Another BGP ASN exists on the device.  '
                            'ASN:{0}'.format(existing.get('asn')))

    bgp_bgp_neighbor_facts = dict(bgp_bgp_neighbor_facts=existing)
    module.exit_json(ansible_facts=bgp_bgp_neighbor_facts,
                     changed=False,
                     warnings=WARNINGS)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
