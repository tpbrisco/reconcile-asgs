#!/usr/bin/env python3
#
# scan-asgs [-D/--debug]
#           [-s/--skip <asg name>]
#           [-r/--skip-re <asg name regular expression>]
#           [-n/--network <banned network>]
#           [-m/--min-cidr <minimum CIDR length (default 22)]
# outputs: list of security groups in the foundation that dont pass
# the check_policy.
#
# sg_network_in_policy encodes
#  - destination CIDR not less than 22 (hard-coded)
#  - list of "banned networks" doesn't overlap with destination CIDR
#
# scan-asgs is an aid in managing application security groups in cloud
# foundry.  This validates that the security group _contents_ pass
# certain policy limits.
#

import os
import sys
import requests
import json
import argparse
import time
import ipaddress

should_verify = False
if not should_verify:
    import urllib3
    urllib3.disable_warnings()


def get_home():
    '''get cf-cli configuration information'''
    cf_home = os.getenv('CF_HOME')
    if cf_home is None:
        cf_home = os.getenv('HOME')
    with open(cf_home + "/.cf/config.json") as c:
        return json.loads(c.read())


def cf_refresh(config):
    '''refresh oauth token'''
    oauth_r = requests.post(config['AuthorizationEndpoint'] + '/oauth/token',
                            data={
                                'refresh_token': config['RefreshToken'],
                                'grant_type': 'refresh_token',
                                'client_id': 'cf'},
                            auth=('cf', ''),
                            verify=should_verify)
    if not oauth_r.ok:
        print("error in token refresh:", oauth_r.json()['error_description'],
              file=sys.stderr)
        sys.exit(1)
    return oauth_r.json()


def compile_networks(nets):
    '''compile_networks(list networks as strings) - list of ipaddress'''
    if type(nets) is not list:
        raise ValueError('expected list of strings')
    ip_n = list()
    for n in nets:
        if n.find('-') > 0:  # ugly range specifier
            n_start, n_end = n.split('-')
            # next - summarize the start/end addresses, but ipaddress
            # returns an iterator, to use list comprehension to make
            # it a list
            ip_n.extend([x for x in ipaddress.summarize_address_range(
                ipaddress.ip_address(n_start),
                ipaddress.ip_address(n_end))])
        else:
            # simpler network constructs - ip addresses and cidr formats
            ip_n.append(ipaddress.ip_network(n))
    ip_n = list(ipaddress.collapse_addresses(ip_n))
    return ip_n


def sg_network_in_policy(sg, args, banned_networks):
    '''check_network_policy(json ASG entity) - validate network policy'''
    # check for exceptions to policy
    if args.skip is not None and sg['name'] in args.skip:
        return True
    # collect all addresses, and apply policy to them in aggregate
    ip_n_list = list()
    for sg_rule in sg['rules']:
        if 'destination' not in sg_rule:
            return False
        ip_n_list.extend(compile_networks([sg_rule['destination']]))
    # take aggregate of addresses, and apply policy - this avoids
    # splitting non-compliant policy across serveral rules to
    # circumvent controls (note that this does not prevent it from
    # being done across multiple policies)
    ip_n_list = list(ipaddress.collapse_addresses(ip_n_list))
    for ip_n in ip_n_list:
        if ip_n.prefixlen < args.min_cidr:
            if args.debug:
                print("%s rule %s fails /%d check" %
                      (sg['name'], ip_n, args.min_cidr))
            return False
        # no referring to banned networks
        for banned in banned_networks:
            if ip_n.overlaps(banned):
                if args.debug:
                    print("%s rule %s fails banned nets" %
                          (sg['name'], ip_n))
                return False
    return True  # network policy passed


def get_sgs(base_url, headers, args):
    '''get_sgs(base_url http string, auth dict) - return list of ASGs'''
    sgs = list()  # empty list of security groups
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    r = s.get(base_url + "/v2/security_groups", verify=should_verify)
    next_page = True
    while next_page:
        next_page = False
        sgs_r = r.json()
        for res in sgs_r['resources']:
            sgs.append(res['entity'])
        # get next page, if it's not empty
        if sgs_r['next_url']:
            r = s.get(sgs_r['next_url'])
            next_page = True
    return sgs


# main
parser = argparse.ArgumentParser(prog='scan-asgs',
                                 description='scan ASGs for policy violations',
                                 fromfile_prefix_chars='@',
                                 epilog='variables can be set in a file, and referenced with @filename - e.g. \"scan-asgs @longlistofargs.txt\"')
parser.add_argument('-D', '--debug',
                    action='store_true',
                    default=False,
                    help='enable debug messages')
parser.add_argument('-s', '--skip-re',
                    action='append',
                    help='regular expression for policy names to skip')
parser.add_argument('-S', '--skip',
                    action='append',
                    help='ASG names to skip policy enforcement')
parser.add_argument('-n', '--network',
                    action='append',
                    help='networks to ban from ASGs')
parser.add_argument('-m', '--min-cidr',
                    action='store',
                    type=int,
                    default=22,
                    help='minimum cidr length allowable (default 22)')
args = parser.parse_args()

# set up configuration for API
config = get_home()
auth_refresh = cf_refresh(config)
headers = {
    'Authorization': auth_refresh['token_type'] +
    ' ' + auth_refresh['access_token']}

# convert/compress networks into ipaddress format; note that we parse
# ranges as well, otherwise we could just use argparse
# type=ipaddress.ip_network
if args.network is not None:
    banned_networks = compile_networks(args.network)
    if args.debug:
        print("Networks:", banned_networks)
else:
    banned_networks = list()

# get all application security groups
asg_get_start = time.time()
all_asgs = get_sgs(config['Target'], headers, args)
asg_get_end = time.time()

# get a list of failing asgs
fail_check_start = time.time()
failing_asgs = list()
fail_check_end = time.time()
for sg in all_asgs:
    if not sg_network_in_policy(sg, args, banned_networks):
        failing_asgs.append(sg)

if args.debug:
    print("get_sgs (%.02fsec): failing (%.02fsec): %s" % (
        (asg_get_end - asg_get_start),
        (fail_check_end - fail_check_start),
        [group['name'] for group in failing_asgs]))
