ate91
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
module: nxos_interface
version_added: "2.1"
short_description: Manages physical attributes of interfaces
description:
    - Manages physical attributes of interfaces of NX-OS switches
author: Jason Edelman (@jedelman8)
notes:
    - This module is also used to create logical interfaces such as
      svis and loopbacks.
    - Be cautious of platform specific idiosyncrasies. For example,
      when you default a loopback interface, the admin state toggles
      on certain versions of NX-OS.
options:
    interface:
        description:
            - Full name of interface, i.e. Ethernet1/1, port-channel10.
        required: true
        default: null
    interface_type:
        description:
            - Interface type to be unconfigured from the device.
        required: false
        default: null
        choices: ['loopback', 'portchannel', 'svi', 'nve']
    admin_state:
        description:
            - Administrative state of the interface
        required: false
        default: up
        choices: ['up','down']
    description:
        description:
            - Interface description
        required: false
        default: null
    mode:
        description:
            - Manage Layer 2 or Layer 3 state of the interface
        required: false
        default: null
        choices: ['layer2','layer3']
    ip_forward:
        description:
            - Enable/Disable ip forward feature on SVIs
        required: false
        default: null
        choices: ['enable','disable']
    state:
        description:
            - Specify desired state of the resource
        required: true
        default: present
        choices: ['present','absent','default']
'''

EXAMPLES = '''
# Ensure an interface is a Layer 3 port and that it has the proper description
- nxos_interface: interface=Ethernet1/1 description='Configured by Ansible' mode=layer3 host=68.170.147.165

# Admin down an interface
- nxos_interface: interface=Ethernet2/1 host=68.170.147.165 admin_state=down

# Remove all loopback interfaces
- nxos_interface: interface=loopback state=absent host=68.170.147.165

# Remove all logical interfaces
- nxos_interface: interface_type={{ item }} state=absent host={{ inventory_hostname }}
  with_items:
    - loopback
    - portchannel
    - svi
    - nve

# Admin up all ethernet interfaces
- nxos_interface: interface=ethernet host=68.170.147.165 admin_state=up

# Admin down ALL interfaces (physical and logical)
- nxos_interface: interface=all host=68.170.147.165 admin_state=down
'''
RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"admin_state": "down"}
existing:
    description: k/v pairs of existing switchport
    type: dict
    sample:  {"admin_state": "up", "description": "None",
              "interface": "port-channel101", "mode": "layer2",
              "type": "portchannel", "ip_forward": "enable"}
end_state:
    description: k/v pairs of switchport after module execution
    returned: always
    type: dict or null
    sample:  {"admin_state": "down", "description": "None",
              "interface": "port-channel101", "mode": "layer2",
              "type": "portchannel", "ip_forward": "enable"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
updates:
    description: command list sent to the device
    returned: always
    type: list
    sample: ["interface port-channel101", "shutdown"]
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
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

def is_default_interface(interface, module):
    """Checks to see if interface exists and if it is a default config

    Args:
        interface (str): full name of interface, i.e. vlan10,
            Ethernet1/1, loopback10

    Returns:
        True: if interface has default config
        False: if it does not have a default config
        DNE (str): if the interface does not exist - loopbacks, SVIs, etc.

    """
    command = 'show run interface ' + interface

    try:
        body = execute_show_command(command, module,
                                    command_type='cli_show_ascii')[0]
    except IndexError:
        body = []

    if body:
        raw_list = body.split('\n')
        found = False
        for line in raw_list:
            if line.startswith('interface'):
                found = True
            if found and line and not line.startswith('interface'):
                return False
        return True

    else:
        return 'DNE'


def get_interface_type(interface):
    """Gets the type of interface
    Args:
        interface (str): full name of interface, i.e. Ethernet1/1, loopback10,
            port-channel20, vlan20
    Returns:
        type of interface: ethernet, svi, loopback, management, portchannel,
         or unknown
    """
    if interface.upper().startswith('ET'):
        return 'ethernet'
    elif interface.upper().startswith('VL'):
        return 'svi'
    elif interface.upper().startswith('LO'):
        return 'loopback'
    elif interface.upper().startswith('MG'):
        return 'management'
    elif interface.upper().startswith('MA'):
        return 'management'
    elif interface.upper().startswith('PO'):
        return 'portchannel'
    elif interface.upper().startswith('NV'):
        return 'nve'
    else:
        return 'unknown'


def get_manual_interface_attributes(interface, module):
    """Gets admin state and description of a SVI interface. Hack due to API.
    Args:
        interface (str): full name of SVI interface, i.e. vlan10
    Returns:
        dictionary that has two k/v pairs: admin_state & description
            if not an svi, returns None
    """

    if get_interface_type(interface) == 'svi':
        command = 'show interface ' + interface
        try:
            body = execute_modified_show_for_cli_text(command, module)[0]
        except (IndexError, ShellError):
            return None

        command_list = body.split('\n')
        desc = None
        admin_state = 'up'
        for each in command_list:
            if 'Description:' in each:
                line = each.split('Description:')
                desc = line[1].strip().split('MTU')[0].strip()
            elif 'Administratively down' in each:
                admin_state = 'down'

        return dict(description=desc, admin_state=admin_state)
    else:
        return None


def get_interface(intf, module):
    """Gets current config/state of interface
    Args:
        intf (string): full name of interface, i.e. Ethernet1/1, loopback10,
            port-channel20, vlan20
    Returns:
      dictionary that has relevant config/state data about the given
          interface based on the type of interface it is
    """
    base_key_map = {
        'interface': 'interface',
        'admin_state': 'admin_state',
        'desc': 'description',
    }
    mode_map = {
        'eth_mode': 'mode'
    }
    loop_map = {
        'state': 'admin_state'
    }
    svi_map = {
        'svi_admin_state': 'admin_state',
        'desc': 'description'
    }
    mode_value_map = {
        "mode": {
            "access": "layer2",
            "trunk": "layer2",
            "routed": "layer3",
            "layer3": "layer3"
        }
    }

    key_map = {}
    interface = {}

    command = 'show interface ' + intf
    try:
        body = execute_show_command(command, module)[0]
    except IndexError:
        body = []

    if body:
        interface_table = body['TABLE_interface']['ROW_interface']
        intf_type = get_interface_type(intf)
        if intf_type in ['portchannel', 'ethernet']:
            if not interface_table.get('eth_mode'):
                interface_table['eth_mode'] = 'layer3'

        if intf_type == 'ethernet':
            key_map.update(base_key_map)
            key_map.update(mode_map)
            temp_dict = apply_key_map(key_map, interface_table)
            temp_dict = apply_value_map(mode_value_map, temp_dict)
            interface.update(temp_dict)

        elif intf_type == 'svi':
            key_map.update(svi_map)
            temp_dict = apply_key_map(key_map, interface_table)
            interface.update(temp_dict)
            attributes = get_manual_interface_attributes(intf, module)
            interface['admin_state'] = str(attributes.get('admin_state',
                                                          'nxapibug'))
            interface['description'] = str(attributes.get('description',
                                                          'nxapi_bug'))
            command = 'show run interface ' + intf
            body = execute_show_command(command, module,
                                        command_type='cli_show_ascii')[0]
            if 'ip forward' in body:
                interface['ip_forward'] = 'enable'
            else:
                interface['ip_forward'] = 'disable'

        elif intf_type == 'loopback':
            key_map.update(base_key_map)
            key_map.pop('admin_state')
            key_map.update(loop_map)
            temp_dict = apply_key_map(key_map, interface_table)
            if not temp_dict.get('description'):
                temp_dict['description'] = "None"
            interface.update(temp_dict)

        elif intf_type == 'management':
            key_map.update(base_key_map)
            temp_dict = apply_key_map(key_map, interface_table)
            interface.update(temp_dict)

        elif intf_type == 'portchannel':
            key_map.update(base_key_map)
            key_map.update(mode_map)
            temp_dict = apply_key_map(key_map, interface_table)
            temp_dict = apply_value_map(mode_value_map, temp_dict)
            if not temp_dict.get('description'):
                temp_dict['description'] = "None"
            interface.update(temp_dict)

        elif intf_type == 'nve':
            key_map.update(base_key_map)
            temp_dict = apply_key_map(key_map, interface_table)
            if not temp_dict.get('description'):
                temp_dict['description'] = "None"
            interface.update(temp_dict)

    interface['type'] = intf_type

    return interface


def get_intf_args(interface):
    intf_type = get_interface_type(interface)

    arguments = ['admin_state', 'description']

    if intf_type in ['ethernet', 'portchannel']:
        arguments.extend(['mode'])
    if intf_type == 'svi':
        arguments.extend(['ip_forward'])

    return arguments


def get_interfaces_dict(module):
    """Gets all active interfaces on a given switch
    Returns:
        dictionary with interface type (ethernet,svi,loop,portchannel) as the
            keys.  Each value is a list of interfaces of given interface (key)
            type.
    """
    command = 'show interface status'
    try:
        body = execute_show_command(command, module)[0]
    except IndexError:
        body = {}

    interfaces = {
        'ethernet': [],
        'svi': [],
        'loopback': [],
        'management': [],
        'portchannel': [],
        'nve': [],
        'unknown': []
        }

    interface_list = body.get('TABLE_interface')['ROW_interface']
    for index  in interface_list:
        intf = index ['interface']
        intf_type = get_interface_type(intf)

        interfaces[intf_type].append(intf)

    return interfaces


def normalize_interface(if_name):
    """Return the normalized interface name
    """
    def _get_number(if_name):
        digits = ''
        for char in if_name:
            if char.isdigit() or char == '/':
                digits += char
        return digits

    if if_name.lower().startswith('et'):
        if_type = 'Ethernet'
    elif if_name.lower().startswith('vl'):
        if_type = 'Vlan'
    elif if_name.lower().startswith('lo'):
        if_type = 'loopback'
    elif if_name.lower().startswith('po'):
        if_type = 'port-channel'
    elif if_name.lower().startswith('nv'):
        if_type = 'nve'
    else:
        if_type = None

    number_list = if_name.split(' ')
    if len(number_list) == 2:
        number = number_list[-1].strip()
    else:
        number = _get_number(if_name)

    if if_type:
        proper_interface = if_type + number
    else:
        proper_interface = if_name

    return proper_interface


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


def apply_value_map(value_map, resource):
    for key, value in value_map.items():
        resource[key] = value[resource.get(key)]
    return resource


def get_interface_config_commands(interface, intf, existing):
    """Generates list of commands to configure on device
    Args:
        interface (str): k/v pairs in the form of a set that should
            be configured on the device
        intf (str): full name of interface, i.e. Ethernet1/1
    Returns:
      list: ordered list of commands to be sent to device
    """

    commands = []
    desc = interface.get('description')
    if desc:
        commands.append('description {0}'.format(desc))

    mode = interface.get('mode')
    if mode:
        if mode == 'layer2':
            command = 'switchport'
        elif mode == 'layer3':
            command = 'no switchport'
        commands.append(command)

    admin_state = interface.get('admin_state')
    if admin_state:
        command = get_admin_state(interface, intf, admin_state)
        commands.append(command)

    ip_forward = interface.get('ip_forward')
    if ip_forward:
        if ip_forward == 'enable':
            command = 'ip forward'
        else:
            command = 'no ip forward'
        commands.append(command)

    if commands:
        commands.insert(0, 'interface ' + intf)

    return commands


def get_admin_state(interface, intf, admin_state):
    if admin_state == 'up':
        command = 'no shutdown'
    elif admin_state == 'down':
        command = 'shutdown'
    return command


def get_proposed(existing, normalized_interface, args):

    # gets proper params that are allowed based on interface type
    allowed_params = get_intf_args(normalized_interface)

    proposed = {}

    # retrieves proper interface params from args (user defined params)
    for param in allowed_params:
        temp = args.get(param)
        if temp:
            proposed[param] = temp

    return proposed


def smart_existing(module, intf_type, normalized_interface):

    # 7K BUG MAY CAUSE THIS TO FAIL

    all_interfaces = get_interfaces_dict(module)
    if normalized_interface in all_interfaces[intf_type]:
        existing = get_interface(normalized_interface, module)
        is_default = is_default_interface(normalized_interface, module)
    else:
        if intf_type == 'ethernet':
            module.fail_json(msg='Invalid Ethernet interface provided.',
                             interface=normalized_interface)
        elif intf_type in ['loopback', 'portchannel', 'svi', 'nve']:
            existing = {}
            is_default = 'DNE'
    return existing, is_default


def execute_config_command(commands, module):
    try:
        module.configure(commands)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending CLI commands',
                         error=str(clie), commands=commands)


def get_cli_body_ssh(command, response, module):
    """Get response for when transport=cli.  This is kind of a hack and mainly
    needed because these modules were originally written for NX-API.  And
    not every command supports "| json" when using cli/ssh.  As such, we assume
    if | json returns an XML string, it is a valid command, but that the
    resource doesn't exist yet.
    """
    if 'xml' in response[0]:
        body = []
    elif 'show run' in command:
        body = response
    else:
        try:
            body = [json.loads(response[0])]
        except ValueError:
            module.fail_json(msg='Command does not support JSON output',
                             command=command)
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


def execute_modified_show_for_cli_text(command, module):
    cmds = [command]
    if module.params['transport'] == 'cli':
        response = execute_show(cmds, module)
    else:
        response = execute_show(cmds, module, command_type='cli_show_ascii')
    body = response
    return body


def flatten_list(command_lists):
    flat_command_list = []
    for command in command_lists:
        if isinstance(command, list):
            flat_command_list.extend(command)
        else:
            flat_command_list.append(command)
    return flat_command_list


def get_interface_type_removed_cmds(interfaces):
    commands = []

    for interface in interfaces:
        if interface != 'Vlan1':
            commands.append('no interface {0}'.format(interface))

    return commands


def main():

    argument_spec = dict(
        interface=dict(required=False,),
        admin_state=dict(default='up', choices=['up', 'down'], required=False),
        description=dict(required=False, default=None),
        mode=dict(choices=['layer2', 'layer3'], required=False),
        interface_type=dict(required=False,
                            choices=['loopback', 'portchannel', 'svi', 'nve']),
        ip_forward=dict(required=False, choices=['enable', 'disable']),
        state=dict(choices=['absent', 'present', 'default'],
                   default='present', required=False),
        include_defaults=dict(default=True)
    )
    module = get_module(argument_spec=argument_spec,
                        mutually_exclusive=[['interface', 'interface_type']],
                        supports_check_mode=True)

    interface = module.params['interface']
    interface_type = module.params['interface_type']
    admin_state = module.params['admin_state']
    description = module.params['description']
    mode = module.params['mode']
    ip_forward = module.params['ip_forward']
    state = module.params['state']

    if interface:
        interface = interface.lower()
        intf_type = get_interface_type(interface)
        normalized_interface = normalize_interface(interface)

        if normalized_interface == 'Vlan1' and state == 'absent':
            module.fail_json(msg='ERROR: CANNOT REMOVE VLAN 1!')

        if intf_type == 'nve':
            if description or mode:
                module.fail_json(msg='description and mode params are not '
                                     'supported in this module. Use '
                                     'nxos_vxlan_vtep instead.')
        if ip_forward and intf_type != 'svi':
            module.fail_json(msg='The ip_forward feature is only available'
                                 ' for SVIs.')
        args = dict(interface=interface, admin_state=admin_state,
                    description=description, mode=mode, ip_forward=ip_forward)

        if intf_type == 'unknown':
            module.fail_json(
                msg='unknown interface type found-1',
                interface=interface)

        existing, is_default = smart_existing(module, intf_type, normalized_interface)
        proposed = get_proposed(existing, normalized_interface, args)
    else:
        intf_type = normalized_interface = interface_type
        proposed = dict(interface_type=interface_type)

    changed = False
    commands = []
    if interface:
        delta = dict()

        if state == 'absent':
            if intf_type in ['svi', 'loopback', 'portchannel', 'nve']:
                if is_default != 'DNE':
                    cmds = ['no interface {0}'.format(normalized_interface)]
                    commands.append(cmds)
            elif intf_type in ['ethernet']:
                if is_default is False:
                    cmds = ['default interface {0}'.format(normalized_interface)]
                    commands.append(cmds)
        elif state == 'present':
            if not existing:
                cmds = get_interface_config_commands(proposed,
                                                     normalized_interface,
                                                     existing)
                commands.append(cmds)
            else:
                delta = dict(set(proposed.iteritems()).difference(
                    existing.iteritems()))
                if delta:
                    cmds = get_interface_config_commands(delta,
                                                         normalized_interface,
                                                         existing)
                    commands.append(cmds)
        elif state == 'default':
            if is_default is False:
                cmds = ['default interface {0}'.format(normalized_interface)]
                commands.append(cmds)
            elif is_default == 'DNE':
                module.exit_json(msg='interface you are trying to default does'
                                     ' not exist')
    elif interface_type:
        if state == 'present':
            module.fail_json(msg='The interface_type param can be used '
                                 'only with state absent.')

        existing = get_interfaces_dict(module)[interface_type]
        cmds = get_interface_type_removed_cmds(existing)
        commands.append(cmds)

    cmds = flatten_list(commands)
    end_state = existing

    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            execute_config_command(cmds, module)
            changed = True
            if module.params['interface']:
                if delta.get('mode'): # or delta.get('admin_state'):
                    # if the mode changes from L2 to L3, the admin state
                    # seems to change after the API call, so adding a second API
                    # call to ensure it's in the desired state.
                    admin_state = delta.get('admin_state') or admin_state
                    c1 = 'interface {0}'.format(normalized_interface)
                    c2 = get_admin_state(delta, normalized_interface, admin_state)
                    cmds2 = [c1, c2]
                    execute_config_command(cmds2, module)
                    cmds.extend(cmds2)
                end_state, is_default = smart_existing(module, intf_type,
                                                       normalized_interface)
            else:
                end_state = get_interfaces_dict(module)[interface_type]

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['end_state'] = end_state
    results['state'] = state
    results['updates'] = cmds
    results['changed'] = changed

    module.exit_json(**results)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
