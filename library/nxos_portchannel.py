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

module: nxos_portchannel
version_added: "2.2"
short_description: Manages port-channel interfaces
description:
    - Manages port-channel specific configuration parameters
extends_documentation_fragment: nxos
author: Jason Edelman (@jedelman8), Gabriele Gerbino (@GGabriele)
notes:
    - Absent removes the portchannel config and interface if it
      already exists. If members to be removed are not explicitly
      passed, all existing members (if any), are removed.
    - Members must be a list
    - LACP needs to be enabled first if active/passive modes are used
options:
    group:
        description:
            - channel-group number for the port-channel
        required: true
    mode:
        description:
            - Mode for the port-channel, i.e. on, active, passive
        required: false
        default: on
        choices: ['active','passive','on']
    min_links:
        description:
            - min links required to keep portchannel up
        required: false
        default: null
    members:
        description:
            - List of interfaces that will be managed in a given portchannel
        required: false
        default: null
    state:
        description:
            - Manage the state of the resource
        required: false
        default: present
        choices: ['present','absent']
'''
EXAMPLES = '''
# Ensure port-channel 99 doesn't exist on the switch
- nxos_portchannel: group=99 host={{ inventory_hostname }} state=absent

# Ensure port-channel99 is created, add two members, and set to mode on
- nxos_portchannel:
    group: 99
    members: ['Ethernet1/1','Ethernet1/2']
    mode: 'active'
    host: "{{ inventory_hostname }}"
    state: present

'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"group": "12", "members": ["Ethernet2/5",
            "Ethernet2/6"], "mode": "on"}
existing:
    description:
        - k/v pairs of existing portchannel
    type: dict
    sample: {"group": "12", "members": ["Ethernet2/5",
            "Ethernet2/6"], "members_detail": {
            "Ethernet2/5": {"mode": "active", "status": "D"},
            "Ethernet2/6": {"mode": "active", "status": "D"}},
            "min_links": null, "mode": "active"}
end_state:
    description: k/v pairs of portchannel info after module execution
    returned: always
    type: dict
    sample: {"group": "12", "members": ["Ethernet2/5",
            "Ethernet2/6"], "members_detail": {
            "Ethernet2/5": {"mode": "on", "status": "D"},
            "Ethernet2/6": {"mode": "on", "status": "D"}},
            "min_links": null, "mode": "on"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "interface Ethernet2/6 ; no channel-group 12 ;
            interface Ethernet2/5 ; no channel-group 12 ;
            interface Ethernet2/6 ; channel-group 12 mode on ;
            interface Ethernet2/5 ; channel-group 12 mode on ;"
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
'''

WARNINGS = []

def execute_config_command(commands, module):
    try:
        output = module.config(commands)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending CLI commands',
                         error=str(clie), commands=commands)
    return output


def get_cli_body_ssh(command, response, module, test):
    """Get response for when transport=cli.  This is kind of a hack and mainly
    needed because these modules were originally written for NX-API.  And
    not every command supports "| json" when using cli/ssh.  As such, we assume
    if | json returns an XML string, it is a valid command, but that the
    resource doesn't exist yet. Instead, we assume if '^' is found in response,
    it is an invalid command.
    """
    if '\n' == response[0] or 'xml' in response[0]:
        body = []
    elif ('^' in response[0] or 'show run' in response[0] or
            'show port-channel summary interface' in command):
        body = response
    else:
        try:
            body = [json.loads(response[0])]
        except ValueError:
            module.exit_json(me=response, cmd=command)
            module.fail_json(msg='Command does not support JSON output',
                             command=command)
    return body


def execute_show(cmds, module, command_type=None):
    try:
        if command_type:
            response = module.cli(cmds, command_type=command_type)
        else:
            response = module.cli(cmds)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending {0}'.format(cmds),
                         error=str(clie))

    return response


def execute_show_command(command, module, command_type='cli_show', test=False):
    if module.params['transport'] == 'cli':
        if 'show port-channel summary' in command:
            command += ' | json'
        elif 'show run' not in command:
            command += ' | xml'
        cmds = [command]
        response = execute_show(cmds, module)
        body = get_cli_body_ssh(command, response, module, test)
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


def get_portchannel_members(pchannel):
    try:
        members = pchannel['TABLE_member']['ROW_member']
    except KeyError:
        members = []

    return members


def get_portchannel_mode(interface, protocol, module):
    if protocol != 'LACP':
        mode = 'on'
    else:
        command = 'show run interface {0}'.format(interface)
        mode = 'unknown'
        find = ''

        body = execute_show_command(command, module)[0]

        if module.params['transport'] == 'cli':
            mode_list = body.split('\n')

            for line in mode_list:
                this_line = line.strip()
                if this_line.startswith('channel-group'):
                    find = this_line
            if 'mode' in find:
                if 'passive' in find:
                    mode = 'passive'
                elif 'active' in find:
                    mode = 'active'
        else:
            try:
                intf_table = body['filter']['configure']['terminal']['interface']
                channel_table = intf_table['__XML__PARAM__interface']['channel-group']
                mode = channel_table['__XML__PARAM__channel-id']['mode'].keys()[0]
            except KeyError:
                return mode

    return mode


def get_min_links(group, module, test):
    command = 'show run interface port-channel{0}'.format(group)
    minlinks = None
    body = execute_show_command(command, module)[0]

    if module.params['transport'] == 'cli':
        ml_list = body.split('\n')

        for line in ml_list:
            this_line = line.strip()
            if 'min-links' in this_line:
                minlinks = str(this_line.split('min-links ')[-1])
    else:
        try:
            intf_table = body['filter']['configure']['terminal']['interface']
            lacp_table = intf_table['__XML__PARAM__interface']['lacp']
            minlinks = lacp_table['min-links']['__XML__PARAM__min-links-number']['__XML__value']
        except KeyError:
            minlinks = None

    return minlinks


def get_portchannel(group, module, test=False):
    command = 'show port-channel summary'
    portchannel = {}
    portchannel_table = {}
    members = []

    if test:
        body = execute_show_command(command, module, test=True)
    else:
        body = execute_show_command(command, module)

    try:
        pc_table = body[0]['TABLE_channel']['ROW_channel']

        if isinstance(pc_table, dict):
            pc_table = [pc_table]

        for pc in pc_table:
            if pc['group'] == group:
                portchannel_table = pc
    except (KeyError, AttributeError, TypeError, IndexError):
        return {}

    if portchannel_table:
        portchannel['group'] = portchannel_table['group']
        protocol = portchannel_table['prtcl']
        members_list = get_portchannel_members(portchannel_table)

        if isinstance(members_list, dict):
            members_list = [members_list]

        member_dictionary = {}
        for each_member in members_list:
            interface = each_member['port']
            members.append(interface)

            pc_member = {}
            pc_member['status'] = str(each_member['port-status'])
            pc_member['mode'] = get_portchannel_mode(interface,
                                                     protocol, module)

            member_dictionary[interface] = pc_member
            portchannel['members'] = members
            portchannel['members_detail'] = member_dictionary
            portchannel['min_links'] = get_min_links(group, module, test)

        # Ensure each member have the same mode.
        modes = set()
        for each, value in member_dictionary.iteritems():
            modes.update([value['mode']])
        if len(modes) == 1:
            portchannel['mode'] = value['mode']
        else:
            portchannel['mode'] = 'unknown'

    return portchannel


def get_portchannel_list(module):
    command = 'show port-channel summary'
    portchannels = []

    body = execute_show_command(command, module)

    try:
        portchannel_table = body[0]['TABLE_channel']['ROW_channel']

        if isinstance(portchannel_table, dict):
            portchannel_table = [portchannel_table]

        for each_portchannel in portchannel_table:
            portchannels.append(each_portchannel['group'])
    except (KeyError, AttributeError, IndexError, TypeError):
        return portchannels

    return portchannels


def config_portchannel(proposed, mode, group):
    commands = []
    config_args = {
        'mode': 'channel-group {group} mode {mode}',
        'min_links': 'lacp min-links {min_links}',
    }

    for member in proposed.get('members', []):
        commands.append('interface {0}'.format(member))
        commands.append(config_args.get('mode').format(group=group, mode=mode))

    min_links = proposed.get('min_links', None)
    if min_links:
        command = 'interface port-channel {0}'.format(group)
        commands.append(command)
        commands.append(config_args.get('min_links').format(
                                                    min_links=min_links))

    return commands


def get_commands_to_add_members(proposed, existing, module):
    try:
        proposed_members = proposed['members']
    except KeyError:
        proposed_members = []

    try:
        existing_members = existing['members']
    except KeyError:
        existing_members = []

    members_to_add = list(set(proposed_members).difference(existing_members))

    commands = []
    if members_to_add:
        for member in members_to_add:
            commands.append('interface {0}'.format(member))
            commands.append('channel-group {0} mode {1}'.format(
                existing['group'], proposed['mode']))

    return commands


def get_commands_to_remove_members(proposed, existing):
    try:
        proposed_members = proposed['members']
    except KeyError:
        proposed_members = []

    try:
        existing_members = existing['members']
    except KeyError:
        existing_members = []

    members_to_remove = list(set(existing_members).difference(proposed_members))

    commands = []
    if members_to_remove:
        for member in members_to_remove:
            commands.append('interface {0}'.format(member))
            commands.append('no channel-group {0}'.format(existing['group']))

    return commands


def get_commands_if_mode_change(proposed, existing, group, mode, module):
    try:
        proposed_members = proposed['members']
    except KeyError:
        proposed_members = []

    try:
        existing_members = existing['members']
    except KeyError:
        existing_members = []

    try:
        members_dict = existing['members_detail']
    except KeyError:
        members_dict = {}

    members_to_remove = set(existing_members).difference(proposed_members)
    members_with_mode_change = []
    if members_dict:
        for interface, values in members_dict.iteritems():
            if (interface in proposed_members and
                    (interface not in members_to_remove)):
                if values['mode'] != mode:
                    members_with_mode_change.append(interface)

    commands = []
    if members_with_mode_change:
        for member in members_with_mode_change:
            commands.append('interface {0}'.format(member))
            commands.append('no channel-group {0}'.format(group))

        for member in members_with_mode_change:
            commands.append('interface {0}'.format(member))
            commands.append('channel-group {0} mode {1}'.format(group, mode))

    return commands


def get_commands_min_links(existing, proposed, group, min_links, module):
    commands = []
    try:
        if (existing['min_links'] is None or
                (existing['min_links'] != proposed['min_links'])):
            commands.append('interface port-channel{0}'.format(group))
            commands.append('lacp min-link {0}'.format(min_links))
    except KeyError:
        commands.append('interface port-channel{0}'.format(group))
        commands.append('lacp min-link {0}'.format(min_links))
    return commands


def main():
    argument_spec = dict(
            group=dict(required=True, type='str'),
            mode=dict(required=False, choices=['on', 'active', 'passive'],
                      default='on', type='str'),
            min_links=dict(required=False, default=None, type='str'),
            members=dict(required=False, default=None, type='list'),
            state=dict(required=False, choices=['absent', 'present'],
                       default='present'),
    )
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    group = str(module.params['group'])
    mode = module.params['mode']
    min_links = module.params['min_links']
    members = module.params['members']
    state = module.params['state']

    if ((min_links or mode) and
            (not members and state == 'present')):
        module.fail_json(msg='"members" is required when state=present and '
                             '"min_links" or "mode" are provided')

    changed = False
    existing = get_portchannel(group, module)

    args = dict(group=group, mode=mode, min_links=min_links, members=members)
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)
    end_state = existing

    commands = []
    changed = False
    active_portchannels = get_portchannel_list(module)

    if state == 'absent':
        if existing:
            commands.append(['no interface port-channel{0}'.format(group)])
    elif state == 'present':
        if group not in active_portchannels:
            command = config_portchannel(proposed, mode, group)
            commands.append(command)
            WARNINGS.append("The proposed port-channel interface did not "
                            "exist. It's recommended to use nxos_interface to "
                            "create all logical interfaces.")

        elif existing and group in active_portchannels:
            command = get_commands_to_remove_members(proposed, existing)
            commands.append(command)

            command = get_commands_to_add_members(proposed, existing, module)
            commands.append(command)

            mode_command = get_commands_if_mode_change(proposed, existing,
                                                       group, mode, module)

            commands.insert(0, mode_command)

            if min_links:
                command = get_commands_min_links(existing, proposed,
                                                 group, min_links, module)
                commands.append(command)

    cmds = flatten_list(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            output = execute_config_command(cmds, module)
            if module.params['transport'] == 'cli':
                output = ' '.join(output)
                if 'command failed' in output:
                    module.fail_json(msg='Port configuration may not be compatible.')
            changed = True
            end_state = get_portchannel(group, module, test=True)

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['end_state'] = end_state
    results['state'] = state
    results['updates'] = cmds
    results['changed'] = changed

    if WARNINGS:
        results['warnings'] = WARNINGS

    module.exit_json(**results)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
