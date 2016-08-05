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
module: nxos_file_copy
short_description: Copy a file to a remote NXOS device over SCP.
description:
    - Copy a file to the flash (or bootflash) remote network device on NXOS devices
notes:
    - The feature must be enabled with feature scp-server.
    - On IOS and Arista EOS, the user must be at privelege 15.
    - If the file is already present (md5 sums match), no transfer will take place.
    - Check mode will tell you if the file would be copied.
options:
    local_file:
        description:
            - Path to local file. Local directory must exist.
        required: true
    remote_file:
        description:
            - Remote file path of the copy. Remote directories must exist.
              If omitted, the name of the local file will be used.
        required: false
        default: null
    file_system:
        description:
            - The remote file system of the device. If omitted,
              devices that support a file_system parameter will use their default values.
        required: false
        default: null
'''

RETURN = '''
transfer_status:
    description: Whether a file was transfered. "No Transfer" or "Sent".
    returned: success
    type: string
    sample: 'Sent'
local_file:
    description: The path of the local file.
    returned: success
    type: string
    sample: '/path/to/local/file'
remote_file:
    description: The path of the remote file.
    returned: success
    type: string
    sample: '/path/to/remote/file'
'''

import os
from scp import SCPClient
import paramiko
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


def verify_remote_file_exists(module, dst, file_system='bootflash:'):
    command = 'dir {0}/{1}'.format(file_system, dst)
    body = execute_show_command(command, module, command_type='cli_show_ascii')
    if 'No such file' in body[0]:
        return 0
    return body[0].split()[0].strip()


def local_file_exists(module):
    return os.path.isfile(module.params['local_file'])


def get_flash_size(module):
    command = 'dir {}'.format(module.params['file_system'])
    body = execute_show_command(command, module, command_type='cli_show_ascii')

    match = re.search(r'(\d+) bytes free', body[0])
    bytes_free = match.group(1)

    return int(bytes_free)


def enough_space(module):
    flash_size = get_flash_size(module)
    file_size = os.path.getsize(module.params['local_file'])
    if file_size > flash_size:
        return False

    return True


def transfer_file(module, dest):
    file_size = os.path.getsize(module.params['local_file'])

    if not local_file_exists(module):
        module.fail_json(msg='Could not transfer file. Local file doesn\'t exist.')

    if not enough_space(module):
        module.fail_json(msg='Could not transfer file. Not enough space on device.')

    hostname = module.params['host']
    username = module.params['username']
    password = module.params['password']

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=hostname,
        username=username,
        password=password)

    full_remote_path = '{}{}'.format(module.params['file_system'], dest)
    scp = SCPClient(ssh.get_transport())
    try:
        scp.put(module.params['local_file'], full_remote_path)
    except Exception as e:
        time.sleep(10)
        temp_size = verify_remote_file_exists(
                    module, dest, file_system=module.params['file_system'])
        if int(temp_size) == int(file_size):
            pass
        else:
            module.fail_json(msg='Could not transfer file. There was an error '
                             'during transfer. Please make sure remote '
                             'permissions are set.', temp_size=temp_size, file_size=file_size)
    finally:
        scp.close()

    return True


def main():
    argument_spec = dict(
            local_file=dict(required=True),
            remote_file=dict(required=False),
            file_system=dict(required=False, default='bootflash:'),
    )
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    local_file = module.params['local_file']
    remote_file = module.params['remote_file']
    file_system = module.params['file_system']

    changed = False
    transfer_status = 'No Transfer'

    if not os.path.isfile(local_file):
        module.fail_json(msg="Local file {} not found".format(local_file))

    dest = remote_file or os.path.basename(local_file)
    remote_exists = remote_file_exists(module, dest, file_system=file_system)

    if not remote_exists:
        changed = True
        file_exists = False
    else:
        file_exists = True

    if not module.check_mode and not file_exists:
        try:
            transfer_file(module, dest)
            transfer_status = 'Sent'
        except Exception as e:
            module.fail_json(msg=str(e))

    if remote_file is None:
        remote_file = os.path.basename(local_file)

    module.exit_json(changed=changed,
                     transfer_status=transfer_status,
                     local_file=local_file,
                     remote_file=remote_file,
                     file_system=file_system)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.shell import *
from ansible.module_utils.netcfg import *
from ansible.module_utils.nxos import *
if __name__ == '__main__':
    main()
