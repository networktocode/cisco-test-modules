## Repo for NXOS Ansible modules development and testing.

The Nexus (NX-OS) Ansible modules for 2.2 have been written in a such a way to be backwards compatible with 2.1.  This document walks through how you can use Ansible 2.1, but take advantage of the newer _feature_ modules in 2.2.

### Step 1 - Obtain the New Modules

Clone the Ansible 2.2 Core Modules from GitHub.

```shell
ntc@ntc:~$ git clone -b stable-2.2 --single-branch https://github.com/ansible/ansible-modules-core.git
```

The modules we care about are now in `ansible-modules-core/network/nxos/`

Navigate to this directory and remove **nxos_template**, **nxos_command**, **nxos_config**, **nxos_facts**.  These need to be removed from this directory as we are **NOT** replacing those four modules with 2.2 modules.  Those four module, like every other Ansible module, are pinned to a specific version of Ansible core whereas the newer _feature_ modules also support 2.1.  

```
$ cd network/nxos
$ rm nxos_template.py
$ rm nxos_command.py
$ rm nxos_config
$ rm nxos_facts.py
```


### Step 2 - Locate the Existing (2.1) modules

You can use the `locate` program within the terminal.

For example:

```
cisco@cisco:~/projects/legacy$ locate nxos_vlan.py
/usr/local/lib/python2.7/dist-packages/ansible/modules/core/network/nxos/nxos_vlan.py
/usr/local/lib/python2.7/dist-packages/ansible/modules/core/network/nxos/nxos_vlan.pyc
```

Here we can see the modules are in the following directory:

```
/usr/local/lib/python2.7/dist-packages/ansible/modules/core/network/nxos/
```

> You may also find the modules in `/etc/ansible` - it depends on how you originally installed Ansible.


### Step 3 - Move New Modules (2.2) to the Location of the Old Modules (2.1)

From within the directory of where your new modules are stored, move them to the location of where your 2.1 modules were.

```
$ sudo mv *.py /usr/local/lib/python2.7/dist-packages/ansible/modules/core/network/nxos/
```




