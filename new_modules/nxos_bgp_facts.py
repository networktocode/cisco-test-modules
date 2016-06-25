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
module: nxos_bgp_facts
version_added: "2.2"
short_description: Retrieve BGP configuration
description:
    - Retrieve BGP configurations on NX-OS switches
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
            - Name of the VRF. The name 'default' is a valid VRF
              representing the global bgp.
        required: false
        default: null
'''
EXAMPLES = '''
# retrieve bgp facts
- nxos_bgp_facts: host={{ inventory_hostname }} username={{ un }} password={{ pwd }}
'''

RETURN = '''
nxos_bgp_facts:
    description:
        - Show BGP facts.
    returned: always
    type: dict
    sample: {"asn": "65535", "bestpath_always_compare_med": false,
             "bestpath_aspath_multipath_relax": false, "bestpath_compare_neighborid": false,
             "bestpath_compare_routerid": false, "bestpath_cost_community_ignore": false,
             "bestpath_med_confed": false, "bestpath_med_missing_as_worst": false,
             "bestpath_med_non_deterministic": false, "cluster_id": "",
             "confederation_id": "10", "confederation_peers": "",
             "disable_policy_batching": false, "disable_policy_batching_ipv4_prefix_list": "",
             "disable_policy_batching_ipv6_prefix_list": "", "enforce_first_as": true,
             "event_history_cli": true, "event_history_detail": false,
             "event_history_events": true, "event_history_periodic": true,
             "fast_external_fallover": true, "flush_routes": false, "graceful_restart": true,
             "graceful_restart_helper": false, "graceful_restart_timers_restart": "120",
             "graceful_restart_timers_stalepath_time": "300", "isolate": true,
             "log_neighbor_changes": false, "maxas_limit": "59",
             "neighbor_down_fib_accelerate": false, "reconnect_interval": "60",
             "router_id": "1.1.1.1", "shutdown": true, "suppress_fib_pending": false,
             "timer_bestpath_limit": "", "timer_bgp_hold": "180",
             "timer_bgp_keepalive": "60", "vrf": "ntc"}
'''

import re


BOOL_PARAMS = [
    'bestpath_always_compare_med',
    'bestpath_aspath_multipath_relax',
    'bestpath_compare_neighborid',
    'bestpath_compare_routerid',
    'bestpath_cost_community_ignore',
    'bestpath_med_confed',
    'bestpath_med_missing_as_worst',
    'bestpath_med_non_deterministic',
    'disable_policy_batching',
    'enforce_first_as',
    'fast_external_fallover',
    'flush_routes',
    'graceful_restart',
    'graceful_restart_helper',
    'isolate',
    'log_neighbor_changes',
    'neighbor_down_fib_accelerate',
    'shutdown',
    'suppress_fib_pending'
]
ARGS =  [
        "asn",
        "bestpath_always_compare_med",
        "bestpath_aspath_multipath_relax",
        "bestpath_compare_neighborid",
        "bestpath_compare_routerid",
        "bestpath_cost_community_ignore",
        "bestpath_med_confed",
        "bestpath_med_missing_as_worst",
        "bestpath_med_non_deterministic",
        "cluster_id",
        "confederation_id",
        "confederation_peers",
        "disable_policy_batching",
        "disable_policy_batching_ipv4_prefix_list",
        "disable_policy_batching_ipv6_prefix_list",
        "enforce_first_as",
        "event_history_cli",
        "event_history_detail",
        "event_history_events",
        "event_history_periodic",
        "fast_external_fallover",
        "flush_routes",
        "graceful_restart",
        "graceful_restart_helper",
        "graceful_restart_timers_restart",
        "graceful_restart_timers_stalepath_time",
        "isolate",
        "log_neighbor_changes",
        "maxas_limit",
        "neighbor_down_fib_accelerate",
        "reconnect_interval",
        "router_id",
        "shutdown",
        "suppress_fib_pending",
        "timer_bestpath_limit",
        "timer_bgp_hold",
        "timer_bgp_keepalive",
        "vrf"
    ]
GLOBAL_PARAMS = [
    'disable_policy_batching',
    'disable_policy_batching_ipv4_prefix_list',
    'disable_policy_batching_ipv6_prefix_list',
    'enforce_first_as',
    'event_history_cli',
    'event_history_detail',
    'event_history_events',
    'event_history_periodic',
    'fast_external_fallover',
    'flush_routes',
    'isolate',
    'shutdown'
]
PARAM_TO_COMMAND_KEYMAP = {
    'bestpath_always_compare_med': 'bestpath always-compare-med',
    'bestpath_aspath_multipath_relax': 'bestpath as-path multipath-relax',
    'bestpath_compare_neighborid': 'bestpath compare-neighborid',
    'bestpath_compare_routerid': 'bestpath compare-routerid',
    'bestpath_cost_community_ignore': 'bestpath cost-community ignore',
    'bestpath_med_confed': 'bestpath med confed',
    'bestpath_med_missing_as_worst': 'bestpath med missing-as-worst',
    'bestpath_med_non_deterministic': 'bestpath med non-deterministic',
    'cluster_id': 'cluster-id',
    'confederation_id': 'confederation identifier',
    'confederation_peers': 'confederation peers',
    'disable_policy_batching': 'disable-policy-batching',
    'disable_policy_batching_ipv4_prefix_list': 'disable-policy-batching ipv4 prefix-list',
    'disable_policy_batching_ipv6_prefix_list': 'disable-policy-batching ipv6 prefix-list',
    'enforce_first_as': 'enforce-first-as',
    'event_history_cli': 'event-history cli',
    'event_history_detail': 'event-history detail',
    'event_history_events': 'event-history events',
    'event_history_periodic': 'event-history periodic',
    'fast_external_fallover': 'fast-external-fallover',
    'flush_routes': 'flush-routes',
    'graceful_restart': 'graceful-restart',
    'graceful_restart_helper': 'graceful-restart-helper',
    'graceful_restart_timers_restart': 'graceful-restart restart-time',
    'graceful_restart_timers_stalepath_time': 'graceful-restart stalepath-time',
    'isolate': 'isolate',
    'log_neighbor_changes': 'log-neighbor-changes',
    'maxas_limit': 'maxas-limit',
    'neighbor_down_fib_accelerate': 'neighbor-down fib-accelerate',
    'reconnect_interval': 'reconnect-interval',
    'router_id': 'router-id',
    'shutdown': 'shutdown',
    'suppress_fib_pending': 'suppress-fib-pending',
    'timer_bestpath_limit': 'timers bestpath-limit',
    'timer_bgp_hold': 'timer bgp',
    'timer_bgp_keepalive': 'timer bpg',
    'vrf': 'vrf'
}


def invoke(name, *args, **kwargs):
    func = globals().get(name)
    if func:
        return func(*args, **kwargs)


def get_custom_value(config, arg):
    if arg.startswith('event_history'):
        REGEX_SIZE = re.compile(r'(?:{0} size\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        REGEX = re.compile(r'\s+{0}\s*$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = False

        if 'no {0}'.format(PARAM_TO_COMMAND_KEYMAP[arg]) in config:
            pass
        elif PARAM_TO_COMMAND_KEYMAP[arg] in config:
            try:
                value = REGEX_SIZE.search(config).group('value')
            except AttributeError:
                if REGEX.search(config):
                    value = True

    elif arg == 'confederation_peers':
        REGEX = re.compile(r'(?:confederation peers\s)(?P<value>.*)$', re.M)
        value = ''
        if 'confederation peers' in config:
            value = REGEX.search(config).group('value').split()

    elif arg == 'timer_bgp_keepalive':
        REGEX = re.compile(r'(?:timers bgp\s)(?P<value>.*)$', re.M)
        value = ''
        if 'timers bgp' in config:
            parsed = REGEX.search(config).group('value').split()
            value = parsed[0]

    elif arg == 'timer_bgp_hold':
        REGEX = re.compile(r'(?:timers bgp\s)(?P<value>.*)$', re.M)
        value = ''
        if 'timers bgp' in config:
            parsed = REGEX.search(config).group('value').split()
            if len(parsed) == 2:
                value = parsed[1]

    return value


def get_value(arg, config):
    custom = [
        'event_history_cli',
        'event_history_events',
        'event_history_periodic',
        'event_history_detail',
        'confederation_peers',
        'timer_bgp_hold',
        'timer_bgp_keepalive'
    ]

    if arg in BOOL_PARAMS:
        REGEX = re.compile(r'\s+{0}\s*$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = False
        try:
            if REGEX.search(config):
                value = True
        except TypeError:
            value = False
    elif arg in custom:
        value = get_custom_value(config, arg)
    else:
        REGEX = re.compile(r'(?:{0}\s)(?P<value>.*)$'.format(PARAM_TO_COMMAND_KEYMAP[arg]), re.M)
        value = ''
        if PARAM_TO_COMMAND_KEYMAP[arg] in config:
            value = REGEX.search(config).group('value')
    return value


def get_bgp_facts(module):
    existing = {}
    netcfg = get_config(module)

    try:
        asn_regex = '.*router\sbgp\s(?P<existing_asn>\d+).*'
        match_asn = re.match(asn_regex, str(netcfg), re.DOTALL)
        existing_asn_group = match_asn.groupdict()
        existing_asn = existing_asn_group['existing_asn']
    except AttributeError:
        existing_asn = ''

    if existing_asn == module.params['asn']:
        bgp_parent = 'router bgp {0}'.format(existing_asn)
        if module.params['vrf'] != 'default':
            parents = [bgp_parent, 'vrf {0}'.format(module.params['vrf'])]
        else:
            parents = bgp_parent

        config = netcfg.get_section(parents)

        if config:
            # remove the asn
            ARGS.pop(0)

            for arg in ARGS:
                if module.params['vrf'] != 'default':
                    if arg not in GLOBAL_PARAMS:
                        existing[arg] = get_value(arg, config)
                else:
                    existing[arg] = get_value(arg, config)

            existing['asn'] = existing_asn
            if module.params['vrf'] == 'default':
                existing['vrf'] = 'default'

    return existing


def main():
    argument_spec = dict(
            asn=dict(required=True, type='str'),
            vrf=dict(required=False, type='str', default='default')
    )
    argument_spec.update(nxos_argument_spec)
    module = get_module(argument_spec=argument_spec,
                        supports_check_mode=True)

    result = dict(changed=False)
    bgp_facts = dict(nxos_bgp_facts=invoke('get_bgp_facts', module))

    module.exit_json(ansible_facts=bgp_facts)


from ansible.module_utils.netcfg import *
from ansible.module_utils.netcmd import *
from ansible.module_utils.nxos import *

if __name__ == '__main__':
    main()
