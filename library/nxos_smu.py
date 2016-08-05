#!/usr/bin/env python

# Copyright 2015 Jason Edelman <jason@networktocode.com>
# Network to Code, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DOCUMENTATION = '''
---
module: nxos_smu
short_description: Perform SMUs on Cisco NX-OS devices.
description:
    - Perform software maintenance upgrades (SMUs) on Cisco NX-OS devices.
notes:
    - The module can only activate and commit a package,
      not remove or deactivate it.
options:
    pkg:
        description:
            - Name of the remote package
        required: true
    file_system:
        description:
            - The remote file system of the device. If omitted,
              devices that support a file_system parameter will use
              their default values.
        required: false
        default: null
'''

import time

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
        cmds = [command]
        body = execute_show(cmds, module)
    elif module.params['transport'] == 'nxapi':
        cmds = [command]
        body = execute_show(cmds, module, command_type=command_type)

    return body


def remote_file_exists(module, dst, file_system='bootflash:'):
    command = 'dir {0}/{1}'.format(file_system, dst)
    body = execute_show_command(command, module, command_type='cli_show_ascii')
    if 'No such file' in body[0]:
        return False
    return True


def execute_config_command(commands, module):
    try:
        response = module.configure(commands)
    except ShellError:
        clie = get_exception()
        module.fail_json(msg='Error sending CLI commands',
                         error=str(clie), commands=commands)
    return response


def apply_patch(module, commands):
    for command in commands:
        response = execute_config_command([command], module)
        time.sleep(5)
        if 'failed' in response:
            module.fail_json(msg="Operation failed!", response=response)


def get_commands(module, pkg, file_system):
    commands = []
    splitted_pkg = pkg.split('.')
    fixed_pkg = '.'.join(splitted_pkg[0:-1])

    command = 'show install inactive'
    inactive_body = execute_show_command(command, module,
                                                command_type='cli_show_ascii')
    command = 'show install active'
    active_body = execute_show_command(command, module,
                                                command_type='cli_show_ascii')

    if fixed_pkg not in inactive_body[0] and fixed_pkg not in active_body[0]:
        commands.append('install add {0}{1}'.format(file_system, pkg))

    if fixed_pkg not in active_body[0]:
        commands.append('install activate {0}{1} force'.format(
                                                            file_system, pkg))
    command = 'show install committed'
    install_body = execute_show_command(command, module,
                                                command_type='cli_show_ascii')
    if fixed_pkg not in install_body[0]:
        commands.append('install commit {0}{1}'.format(file_system, pkg))

    return commands


def main():
    argument_spec = dict(
            pkg=dict(required=True),
            file_system=dict(required=False, default='bootflash:'),
    )
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    pkg = module.params['pkg']
    file_system = module.params['file_system']
    changed = False
    remote_exists = remote_file_exists(module, pkg, file_system=file_system)

    if not remote_exists:
        module.fail_json(msg="The requested package does't exist "
                             "on the device")

    commands = get_commands(module, pkg, file_system)
    if not module.check_mode and commands:
        try:
            apply_patch(module, commands)
            changed=True
        except Exception as e:
            module.fail_json(msg=str(e))

    module.exit_json(changed=changed,
                     pkg=pkg,
                     file_system=file_system,
                     updates=commands)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
