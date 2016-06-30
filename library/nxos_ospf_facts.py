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
module: nxos_ospf_facts
version_added: "2.2"
short_description: Retrieve a list of all ospf instances.
description:
    - Retrieve configuration of an ospf instance.
author: Gabriele Gerbino (@GGabriele)
extends_documentation_fragment: nxos
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


def main():
    argument_spec = dict()
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    existing = invoke('get_existing', module)

    ospf_facts = dict(ospf_facts=existing)
    module.exit_json(ansible_facts=ospf_facts,
                     changed=False)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
