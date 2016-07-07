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
module: nxos_vpc
version_added: "2.2"
short_description: Manages global VPC configuration
description:
    - Manages global VPC configuration
extends_documentation_fragment: nxos
author: Jason Edelman (@jedelman8), Gabriele Gerbino (@GGabriele)
notes:
    - The feature vpc must be enabled before this module can be used
    - If not using management vrf, vrf must be globally on the device
      before using in the pkl config
    - Although source IP isn't required on the command line it is
      required when using this module.  The PKL VRF must also be configured
      prior to using this module.
    - Both pkl_src and pkl_dest are needed when changing PKL VRF.
options:
    domain:
        description:
            - VPC domain
        required: true
    role_priority:
        description:
            - Role priority for device. Remember lower is better.
        required: false
        default: null
    system_priority:
        description:
            - System priority device.  Remember they must match between peers.
        required: false
        default: null
    pkl_src:
        description:
            - Source IP address used for peer keepalive link
        required: false
        default: null
    pkl_dest:
        description:
            - Destination (remote) IP address used for peer keepalive link
        required: false
        default: null
    pkl_vrf:
        description:
            - VRF used for peer keepalive link
        required: false
        default: management
    peer_gw:
        description:
            - Enables/Disables peer gateway
        required: true
        choices: ['true','false']
    auto_recovery:
        description:
            - Enables/Disables auto recovery
        required: true
        choices: ['true','false']
    delay_restore:
        description:
            - manages delay restore command and config value in seconds
        required: false
        default: null
    state:
        description:
            - Manages desired state of the resource
        required: true
        choices: ['present','absent']
'''

EXAMPLES = '''
# ensure vpc domain 100 is configured
- nxos_vpc: domain=100 role_priority=1000 system_priority=2000 pkl_src=192.168.100.1 pkl_dest=192.168.100.2 host=68.170.147.165
# ensure peer gateway is enabled for vpc domain 100
- nxos_vpc: domain=100 peer_gw=true host=68.170.147.165
# ensure vpc domain does not exist on switch
- nxos_vpc: domain=100 host=68.170.147.165 state=absent
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
    not every command supports "| json" when using cli/ssh.
    """
    if '^' == response[0]:
        body = []
    elif 'running' in command:
        body = response
    else:
        if command in response[0]:
            response = [response[0].split(command)[1]]
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
        module.fail_json(msg='Error sending {0}'.format(cmds),
                         error=str(clie))
    return response


def execute_show_command(command, module, command_type='cli_show'):
    if module.params['transport'] == 'cli':
        if "section" not in command:
            command += ' | json'
        cmds = [command]
        response = execute_show(cmds, module)
        body = get_cli_body_ssh(command, response, module)
    elif module.params['transport'] == 'nxapi':
        cmds = [command]
        body = execute_show(cmds, module, command_type=command_type)

    return body


def flatten_list(command_lists):
    flat_command_list = []
    for command in command_lists:
        if isinstance(command, list):
            flat_command_list.extend(command)
        else:
            flat_command_list.append(command)
    return flat_command_list


def get_vrf_list(module):
    command = 'show vrf all'
    vrf_table = None

    body = execute_show_command(command, module)

    try:
        vrf_table = body[0]['TABLE_vrf']['ROW_vrf']
    except (KeyError, AttributeError):
        return []

    vrf_list = []
    if vrf_table:
        for each in vrf_table:
            vrf_list.append(str(each['vrf_name'].lower()))

    return vrf_list


def get_autorecovery(auto):
    auto_recovery = auto.split(' ')[0]
    if 'enabled' in auto_recovery.lower():
        return True
    else:
        return False


def get_vpc_running_config(module):
    command = 'show running section vpc'
    body = execute_show_command(command, module, command_type='cli_show_ascii')

    return body


def get_vpc(module):
    vpc = {}

    command = 'show vpc'
    body = execute_show_command(command, module)[0]
    domain = str(body['vpc-domain-id'])
    auto_recovery = get_autorecovery(str(
            body['vpc-auto-recovery-status']))

    if domain != 'not configured':
        delay_restore = None
        pkl_src = None
        role_priority = None
        system_priority = None
        pkl_dest = None
        pkl_vrf = None
        peer_gw = False

        run = get_vpc_running_config(module)[0]
        if run:
            vpc_list = run.split('\n')
            for each in vpc_list:
                if 'delay restore' in each:
                    line = each.split()
                    if len(line) == 5:
                        delay_restore = line[-1]
                if 'peer-keepalive destination' in each:
                    line = each.split()
                    pkl_dest = line[2]
                    for word in line:
                        if 'source' in word:
                            index = line.index(word)
                            pkl_src = line[index + 1]
                if 'role priority' in each:
                    line = each.split()
                    role_priority = line[-1]
                if 'system-priority' in each:
                    line = each.split()
                    system_priority = line[-1]
                if 'peer-gateway' in each:
                    peer_gw = True


        command = 'show vpc peer-keepalive'
        body = execute_show_command(command, module)[0]

        if body:
            pkl_dest = body['vpc-keepalive-dest']
            if 'N/A' in pkl_dest:
                pkl_dest = None
            elif len(pkl_dest) == 2:
                pkl_dest = pkl_dest[0]
            pkl_vrf = str(body['vpc-keepalive-vrf'])

        vpc['domain'] = domain
        vpc['auto_recovery'] = auto_recovery
        vpc['delay_restore'] = delay_restore
        vpc['pkl_src'] = pkl_src
        vpc['role_priority'] = role_priority
        vpc['system_priority'] = system_priority
        vpc['pkl_dest'] = pkl_dest
        vpc['pkl_vrf'] = pkl_vrf
        vpc['peer_gw'] = peer_gw
    else:
        vpc = {}

    return vpc


def get_commands_to_config_vpc(module, vpc, domain, existing):
    vpc = dict(vpc)

    domain_only = vpc.get('domain')
    pkl_src = vpc.get('pkl_src')
    pkl_dest = vpc.get('pkl_dest')
    pkl_vrf = vpc.get('pkl_vrf') or existing.get('pkl_vrf')
    vpc['pkl_vrf'] = pkl_vrf

    commands = []
    if pkl_src or pkl_dest:
        if pkl_src is None:
            vpc['pkl_src'] = existing.get('pkl_src')
        elif pkl_dest is None:
            vpc['pkl_dest'] = existing.get('pkl_dest')
        pkl_command = 'peer-keepalive destination {pkl_dest}'.format(**vpc) \
                      + ' source {pkl_src} vrf {pkl_vrf}'.format(**vpc)
        commands.append(pkl_command)
    elif pkl_vrf:
        pkl_src = existing.get('pkl_src')
        pkl_dest = existing.get('pkl_dest')
        if pkl_src and pkl_dest:
            pkl_command = ('peer-keepalive destination {0}'
                          ' source {1} vrf {2}'.format(pkl_dest, pkl_src, pkl_vrf))
            commands.append(pkl_command)

    if vpc.get('auto_recovery') == False:
        vpc['auto_recovery'] = 'no'
    else:
        vpc['auto_recovery'] = ''

    if vpc.get('peer_gw') == False:
        vpc['peer_gw'] = 'no'
    else:
        vpc['peer_gw'] = ''

    CONFIG_ARGS = {
        'role_priority': 'role priority {role_priority}',
        'system_priority': 'system-priority {system_priority}',
        'delay_restore': 'delay restore {delay_restore}',
        'peer_gw': '{peer_gw} peer-gateway',
        'auto_recovery': '{auto_recovery} auto-recovery',
        }

    for param, value in vpc.iteritems():
        command = CONFIG_ARGS.get(param, 'DNE').format(**vpc)
        if command and command != 'DNE':
            commands.append(command.strip())
        command = None

    if commands or domain_only:
        commands.insert(0, 'vpc domain {0}'.format(domain))
    return commands


def get_commands_to_remove_vpc_interface(portchannel, config_value):
    commands = []
    command = 'no vpc {0}'.format(config_value)
    commands.append(command)
    commands.insert(0, 'interface port-channel{0}'.format(portchannel))
    return commands


def main():
    argument_spec = dict(
            domain=dict(required=True, type='str'),
            role_priority=dict(required=False, type='str'),
            system_priority=dict(required=False, type='str'),
            pkl_src=dict(required=False),
            pkl_dest=dict(required=False),
            pkl_vrf=dict(required=False, default='management'),
            peer_gw=dict(required=True, choices=BOOLEANS, type='bool'),
            auto_recovery=dict(required=True, choices=BOOLEANS, type='bool'),
            delay_restore=dict(required=False, type='str'),
            state=dict(choices=['absent', 'present'], default='present'),
    )
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    domain = module.params['domain']
    role_priority = module.params['role_priority']
    system_priority = module.params['system_priority']
    pkl_src = module.params['pkl_src']
    pkl_dest = module.params['pkl_dest']
    pkl_vrf = module.params['pkl_vrf']
    peer_gw = module.params['peer_gw']
    auto_recovery = module.params['auto_recovery']
    delay_restore = module.params['delay_restore']
    state = module.params['state']

    args = dict(domain=domain, role_priority=role_priority,
                system_priority=system_priority, pkl_src=pkl_src,
                pkl_dest=pkl_dest, pkl_vrf=pkl_vrf, peer_gw=peer_gw,
                auto_recovery=auto_recovery,
                delay_restore=delay_restore)

    if not (pkl_src and pkl_dest and pkl_vrf):
        # if only the source or dest is set, it'll fail and ask to set the
        # other
        if pkl_src or pkl_dest:
            module.fail_json(msg='source AND dest IP for pkl are required at '
                                 'this time (although source is technically not '
                                 ' required by the device.)')

        args.pop('pkl_src')
        args.pop('pkl_dest')
        args.pop('pkl_vrf')

    if pkl_vrf:
        if pkl_vrf.lower() not in get_vrf_list(module):
            module.fail_json(msg='The VRF you are trying to use for the peer '
                                 'keepalive link is not on device yet. Add it'
                                 ' first, please.')
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)
    changed = False
    existing = get_vpc(module)
    end_state = existing

    commands = []
    if state == 'present':
        delta = set(proposed.iteritems()).difference(existing.iteritems())
        if delta:
            command = get_commands_to_config_vpc(module, delta, domain, existing)
            commands.append(command)
    elif state == 'absent':
        if existing:
            if domain != existing['domain']:
                module.fail_json(msg="You are trying to remove a domain that "
                                     "does not exist on the device")
            else:
                commands.append('no vpc domain {0}'.format(domain))

    cmds = flatten_list(commands)

    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            execute_config_command(cmds, module)
            end_state = get_vpc(module)

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
