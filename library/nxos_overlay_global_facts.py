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
module: nxos_overlay_global_facts
version_added: "2.2"
short_description: Retrieve overlay global configuration.
description:
    - Retrieve overlay global configuration.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
'''

PARAM_TO_COMMAND_KEYMAP = {
    'anycast_gateway_mac': 'fabric forwarding anycast-gateway-mac',
}
ARGS =  [
        'anycast_gateway_mac'
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
    config = str(get_config(module))

    for arg in ARGS:
        existing[arg] = get_value(arg, config, module)
    return existing


def main():
    argument_spec = dict()
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    overlay_global_facts = dict(overlay_global_facts=existing)
    module.exit_json(ansible_facts=overlay_global_facts,
                     changed=False)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
