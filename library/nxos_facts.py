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
module: nxos_facts
version_added: "2.1"
short_description: Gets facts about NX-OS switches
description:
    - Offers ability to extract facts from device
extends_documentation_fragment: nxos
author: Jason Edelman (@jedelman8), Gabriele Gerbino (@GGabriele)
'''

EXAMPLES = '''
# retrieve facts
- nxos_facts: host=68.170.147.165
'''

RETURN = '''
facts:
    description:
        - Show multiple information about device.
          These include interfaces, vlans, module and environment information.
    returned: always
    type: dict
    sample: {"fan_info": [{"direction":"front-to-back","hw_ver": "--",
            "model":"N9K-C9300-FAN2","name":"Fan1(sys_fan1)","status":"Ok"}],
            "hostname": "N9K2","interfaces": ["mgmt0","Ethernet1/1"],
            "kickstart": "6.1(2)I3(1)","module": [{"model": "N9K-C9396PX",
            "ports": "48","status": "active *"}],"os": "6.1(2)I3(1)",
            "platform": "Nexus9000 C9396PX Chassis","power_supply_info": [{
            "actual_output": "0 W","model": "N9K-PAC-650W","number": "1",
            "status":"Shutdown"}], "vlan_list":[{"admin_state":"noshutdown",
            "interfaces":["Ethernet1/1"], "name": "default",
            "state": "active","vlan_id": "1"}]}
'''

# COMMON CODE FOR MIGRATION

import re
import time
import collections
import itertools
import shlex
import itertools

from ansible.module_utils.basic import BOOLEANS_TRUE, BOOLEANS_FALSE

DEFAULT_COMMENT_TOKENS = ['#', '!']

class ConfigLine(object):

    def __init__(self, text):
        self.text = text
        self.children = list()
        self.parents = list()
        self.raw = None

    @property
    def line(self):
        line = ['set']
        line.extend([p.text for p in self.parents])
        line.append(self.text)
        return ' '.join(line)

    def __str__(self):
        return self.raw

    def __eq__(self, other):
        if self.text == other.text:
            return self.parents == other.parents

    def __ne__(self, other):
        return not self.__eq__(other)

def ignore_line(text, tokens=None):
    for item in (tokens or DEFAULT_COMMENT_TOKENS):
        if text.startswith(item):
            return True

def get_next(iterable):
    item, next_item = itertools.tee(iterable, 2)
    next_item = itertools.islice(next_item, 1, None)
    return itertools.izip_longest(item, next_item)

def parse(lines, indent, comment_tokens=None):
    toplevel = re.compile(r'\S')
    childline = re.compile(r'^\s*(.+)$')

    ancestors = list()
    config = list()

    for line in str(lines).split('\n'):
        text = str(re.sub(r'([{};])', '', line)).strip()

        cfg = ConfigLine(text)
        cfg.raw = line

        if not text or ignore_line(text, comment_tokens):
            continue

        # handle top level commands
        if toplevel.match(line):
            ancestors = [cfg]

        # handle sub level commands
        else:
            match = childline.match(line)
            line_indent = match.start(1)
            level = int(line_indent / indent)
            parent_level = level - 1

            cfg.parents = ancestors[:level]

            if level > len(ancestors):
                config.append(cfg)
                continue

            for i in range(level, len(ancestors)):
                ancestors.pop()

            ancestors.append(cfg)
            ancestors[parent_level].children.append(cfg)

        config.append(cfg)

    return config


class CustomNetworkConfig(object):

    def __init__(self, indent=None, contents=None, device_os=None):
        self.indent = indent or 1
        self._config = list()
        self._device_os = device_os

        if contents:
            self.load(contents)

    @property
    def items(self):
        return self._config

    @property
    def lines(self):
        lines = list()
        for item, next_item in get_next(self.items):
            if next_item is None:
                lines.append(item.line)
            elif not next_item.line.startswith(item.line):
                lines.append(item.line)
        return lines

    def __str__(self):
        text = ''
        for item in self.items:
            if not item.parents:
                expand = self.get_section(item.text)
                text += '%s\n' % self.get_section(item.text)
        return str(text).strip()

    def load(self, contents):
        self._config = parse(contents, indent=self.indent)

    def load_from_file(self, filename):
        self.load(open(filename).read())

    def get(self, path):
        if isinstance(path, basestring):
            path = [path]
        for item in self._config:
            if item.text == path[-1]:
                parents = [p.text for p in item.parents]
                if parents == path[:-1]:
                    return item

    def search(self, regexp, path=None):
        regex = re.compile(r'^%s' % regexp, re.M)

        if path:
            parent = self.get(path)
            if not parent or not parent.children:
                return
            children = [c.text for c in parent.children]
            data = '\n'.join(children)
        else:
            data = str(self)

        match = regex.search(data)
        if match:
            if match.groups():
                values = match.groupdict().values()
                groups = list(set(match.groups()).difference(values))
                return (groups, match.groupdict())
            else:
                return match.group()

    def findall(self, regexp):
        regexp = r'%s' % regexp
        return re.findall(regexp, str(self))

    def expand(self, obj, items):
        block = [item.raw for item in obj.parents]
        block.append(obj.raw)

        current_level = items
        for b in block:
            if b not in current_level:
                current_level[b] = collections.OrderedDict()
            current_level = current_level[b]
        for c in obj.children:
            if c.raw not in current_level:
                current_level[c.raw] = collections.OrderedDict()

    def to_lines(self, section):
        lines = list()
        for entry in section[1:]:
            line = ['set']
            line.extend([p.text for p in entry.parents])
            line.append(entry.text)
            lines.append(' '.join(line))
        return lines

    def to_block(self, section):
        return '\n'.join([item.raw for item in section])

    def get_section(self, path):
        try:
            section = self.get_section_objects(path)
            if self._device_os == 'junos':
                return self.to_lines(section)
            return self.to_block(section)
        except ValueError:
            return list()

    def get_section_objects(self, path):
        if not isinstance(path, list):
            path = [path]
        obj = self.get_object(path)
        if not obj:
            raise ValueError('path does not exist in config')
        return self.expand_section(obj)

    def expand_section(self, configobj, S=None):
        if S is None:
            S = list()
        S.append(configobj)
        for child in configobj.children:
            if child in S:
                continue
            self.expand_section(child, S)
        return S

    def flatten(self, data, obj=None):
        if obj is None:
            obj = list()
        for k, v in data.items():
            obj.append(k)
            self.flatten(v, obj)
        return obj

    def get_object(self, path):
        for item in self.items:
            if item.text == path[-1]:
                parents = [p.text for p in item.parents]
                if parents == path[:-1]:
                    return item

    def get_children(self, path):
        obj = self.get_object(path)
        if obj:
            return obj.children

    def difference(self, other, path=None, match='line', replace='line'):
        updates = list()

        config = self.items
        if path:
            config = self.get_children(path) or list()

        if match == 'line':
            for item in config:
                if item not in other.items:
                    updates.append(item)

        elif match == 'strict':
            if path:
                current = other.get_children(path) or list()
            else:
                current = other.items

            for index, item in enumerate(config):
                try:
                    if item != current[index]:
                        updates.append(item)
                except IndexError:
                    updates.append(item)

        elif match == 'exact':
            if path:
                current = other.get_children(path) or list()
            else:
                current = other.items

            if len(current) != len(config):
                updates.extend(config)
            else:
                for ours, theirs in itertools.izip(config, current):
                    if ours != theirs:
                        updates.extend(config)
                        break

        if self._device_os == 'junos':
            return updates

        diffs = collections.OrderedDict()
        for update in updates:
            if replace == 'block' and update.parents:
                update = update.parents[-1]
            self.expand(update, diffs)

        return self.flatten(diffs)

    def replace(self, replace, text=None, regex=None, parents=None,
            add_if_missing=False, ignore_whitespace=False):
        match = None

        parents = parents or list()
        if text is None and regex is None:
            raise ValueError('missing required arguments')

        if not regex:
            regex = ['^%s$' % text]

        patterns = [re.compile(r, re.I) for r in to_list(regex)]

        for item in self.items:
            for regexp in patterns:
                string = item.text if ignore_whitespace is True else item.raw
                if regexp.search(item.text):
                    if item.text != replace:
                        if parents == [p.text for p in item.parents]:
                            match = item
                            break

        if match:
            match.text = replace
            indent = len(match.raw) - len(match.raw.lstrip())
            match.raw = replace.rjust(len(replace) + indent)

        elif add_if_missing:
            self.add(replace, parents=parents)


    def add(self, lines, parents=None):
        """Adds one or lines of configuration
        """

        ancestors = list()
        offset = 0
        obj = None

        ## global config command
        if not parents:
            for line in to_list(lines):
                item = ConfigLine(line)
                item.raw = line
                if item not in self.items:
                    self.items.append(item)

        else:
            for index, p in enumerate(parents):
                try:
                    i = index + 1
                    obj = self.get_section_objects(parents[:i])[0]
                    ancestors.append(obj)

                except ValueError:
                    # add parent to config
                    offset = index * self.indent
                    obj = ConfigLine(p)
                    obj.raw = p.rjust(len(p) + offset)
                    if ancestors:
                        obj.parents = list(ancestors)
                        ancestors[-1].children.append(obj)
                    self.items.append(obj)
                    ancestors.append(obj)

            # add child objects
            for line in to_list(lines):
                # check if child already exists
                for child in ancestors[-1].children:
                    if child.text == line:
                        break
                else:
                    offset = len(parents) * self.indent
                    item = ConfigLine(line)
                    item.raw = line.rjust(len(line) + offset)
                    item.parents = ancestors
                    ancestors[-1].children.append(item)
                    self.items.append(item)


def argument_spec():
    return dict(
        # config options
        running_config=dict(aliases=['config']),
        save_config=dict(type='bool', default=False, aliases=['save'])
    )
nxos_argument_spec = argument_spec()

def get_config(module):
    config = module.params['running_config']
    if not config:
        config = module.get_config()
    return CustomNetworkConfig(indent=2, contents=config)

def load_config(module, candidate):
    config = get_config(module)

    commands = candidate.difference(config)
    commands = [str(c).strip() for c in commands]

    save_config = module.params['save_config']

    result = dict(changed=False)

    if commands:
        if not module.check_mode:
            module.configure(commands)
            if save_config:
                module.config.save_config()

        result['changed'] = True
        result['updates'] = commands

    return result
# END OF COMMON CODE

def get_cli_body_ssh(command, response, module):
    if 'xml' in response[0]:
        body = []
    else:
        body = [json.loads(response[0])]
    return body


def execute_show(cmds, module, command_type=None):
    try:
        if command_type:
            response = module.execute(cmds, command_type=command_type)
        else:
            response = module.execute(cmds)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending {0}'.format(command),
                         error=str(clie))
    return response


def execute_show_command(command, module, command_type='cli_show'):
    if module.params['transport'] == 'cli':
        command += ' | json'
        cmds = [command]
        response = execute_show(cmds, module)
        body = get_cli_body_ssh(command, response, module)
    elif module.params['transport'] == 'nxapi':
        cmds = [command]
        body = execute_show(cmds, module, command_type=command_type)

    return body


def apply_key_map(key_map, table):
    new_dict = {}
    for key, value in table.items():
        new_key = key_map.get(key)
        if new_key:
            value = table.get(key)
            if value:
                new_dict[new_key] = str(value)
            else:
                new_dict[new_key] = value
    return new_dict


def get_show_version_facts(module):
    command = 'show version'
    body = execute_show_command(command, module)[0]

    key_map = {
                "kickstart_ver_str": "os",
                "chassis_id": "platform",
                "host_name": "hostname"
            }

    mapped_show_version_facts = apply_key_map(key_map, body)
    return mapped_show_version_facts


def get_interface_facts(module):
    command = 'show interface status'
    body = execute_show_command(command, module)[0]

    interface_list = []
    interface_table = body['TABLE_interface']['ROW_interface']

    if isinstance(interface_table, dict):
        interface_table = [interface_table]

    for each in interface_table:
        interface = str(each.get('interface', None))
        if interface:
            interface_list.append(interface)
    return interface_list


def get_show_module_facts(module):
    command = 'show module'
    body = execute_show_command(command, module)[0]

    module_facts = []
    module_table = body['TABLE_modinfo']['ROW_modinfo']

    key_map = {
                "ports": "ports",
                "type": "type",
                "model": "model",
                "status": "status"
            }

    if isinstance(module_table, dict):
        module_table = [module_table]

    for each in module_table:
        mapped_module_facts = apply_key_map(key_map, each)
        module_facts.append(mapped_module_facts)
    return module_facts


def get_environment_facts(module):
    command = 'show environment'
    body = execute_show_command(command, module)[0]

    powersupply = get_powersupply_facts(body)
    fan = get_fan_facts(body)

    return (powersupply, fan)


def get_powersupply_facts(body):
    powersupply_facts = []
    powersupply_table = body['powersup']['TABLE_psinfo']['ROW_psinfo']

    key_map = {
                "psnum": "number",
                "psmodel": "model",
                "actual_out": "actual_output",
                "actual_in": "actual_input",
                "total_capa": "total_capacity",
                "ps_status": "status"
            }

    if isinstance(powersupply_table, dict):
        powersupply_table = [powersupply_table]

    for each in powersupply_table:
        mapped_powersupply_facts = apply_key_map(key_map, each)
        powersupply_facts.append(mapped_powersupply_facts)
    return powersupply_facts


def get_fan_facts(body):
    fan_facts = []
    fan_table = body['fandetails']['TABLE_faninfo']['ROW_faninfo']

    key_map = {
                "fanname": "name",
                "fanmodel": "model",
                "fanhwver": "hw_ver",
                "fandir": "direction",
                "fanstatus": "status"
            }

    if isinstance(fan_table, dict):
        fan_table = [fan_table]

    for each in fan_table:
        mapped_fan_facts = apply_key_map(key_map, each)
        fan_facts.append(mapped_fan_facts)
    return fan_facts


def get_vlan_facts(module):
    command = 'show vlan brief'
    body = execute_show_command(command, module)[0]

    vlan_list = []
    vlan_table = body['TABLE_vlanbriefxbrief']['ROW_vlanbriefxbrief']

    if isinstance(vlan_table, dict):
        vlan_table = [vlan_table]

    for each in vlan_table:
        vlan = str(each.get('vlanshowbr-vlanid-utf', None))
        if vlan:
            vlan_list.append(vlan)
    return vlan_list


def main():
    argument_spec = dict()
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    # Get 'show version' facts.
    show_version = get_show_version_facts(module)

    # Get interfaces facts.
    interfaces_list = get_interface_facts(module)

    # Get module facts.
    show_module = get_show_module_facts(module)

    # Get environment facts.
    powersupply, fan = get_environment_facts(module)

    # Get vlans facts.
    vlan = get_vlan_facts(module)

    facts = dict(
        interfaces_list=interfaces_list,
        module=show_module,
        power_supply_info=powersupply,
        fan_info=fan,
        vlan_list=vlan)

    facts.update(show_version)

    module.exit_json(ansible_facts=facts)



from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
