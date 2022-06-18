#!/usr/bin/env python3
#
# reconcile-asgs.py [list of yaml]
# changes the list of security groups in the foundation that are not named
# in the [list of yaml] files, and fixes any global running/staging bindings.
#
# reconcile-asgs is an aid in managing application security groups in
# cloud foundry.  As security groups are added/deleted/changed over
# time, it is simple for configuration drift to occur.
#
# Reconcile the security groups listed in the yaml files against the
# security groups in a running foundation.  Lists the security groups
# in the foundation that are not indicated in the YAML files.  These
# are security groups that could/should be deleted.
# The configuration file indicates the global bindings (running, staging)
# that should be configured -- if differences there are detected, they
# are changed to the intended state.
#

import os
import sys
import requests
import json
import yaml
import argparse
import time


# for debugging, export PYTHONWARNINGS="ignore:Unverified HTTPS request"
should_verify = False
if not should_verify:
    import urllib3
    urllib3.disable_warnings()


class ASGException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return 'ASG Exception: {0}'.format(self.message)


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


# accrued message
__output_message = {}


def message(format, type, data):
    '''message(format="text", type, data) - print/collect possibly json formatted messages'''
    # print("format={} type={} data={}".format(format, type, json.dumps(data)))
    if not format:
        print("would {}: {}".format(type, json.dumps(data, indent=2)))
        return
    # check message types
    if type not in ['deleted',
                    'unbind_staging', 'bind_staging',
                    'unbind_running', 'bind_running']:
        print("erorr in message type {}: unknown type".format(type),
              file=sys.stderr)
        sys.exit(1)
    if type in __output_message:
        __output_message[type]['groups'].append(data.copy())
    else:
        __output_message[type] = {'groups': [data.copy()]}


def dump_message(format, run_mode):
    if not format:
        return
    if run_mode:
        run_msg = 'executing'
    else:
        run_msg = 'advising'
    print(json.dumps({'mode': run_msg, 'data': __output_message}, indent=2))


def get_running_asgs(base_url, headers):
    return get_global_sgs(base_url,
                          '/v2/config/running_security_groups',
                          headers)


def get_staging_asgs(base_url, headers):
    return get_global_sgs(base_url,
                          '/v2/config/staging_security_groups',
                          headers)


def get_global_sgs(base_url, runorstage, headers):
    '''get_sgs(base_url http string, auth dict) - return list of ASGs'''
    sgs = dict()  # empty list of security groups
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    r = s.get(base_url + runorstage, verify=should_verify)
    if not r.ok:
        raise ASGException('get_global_sgs fails: {0}'.format(r.url))
    next_page = True
    while (next_page):
        next_page = False
        sgs_r = r.json()
        for res in sgs_r['resources']:
            # get globally bound security groups only
            entity = res['entity']
            sgs[entity['name']] = {
                'name': entity['name'],
                'running_default': entity['running_default'],
                'staging_default': entity['staging_default']}
        if sgs_r['next_url']:
            r = s.get(sgs_r['next_url'])
            if not r.ok:
                raise ASGException('next URL failed {0}'.format(r.url))
            next_page = True
    return sgs


def delete_sgs(enforcing, base_url, headers, sgs):
    '''delete_sgs(base_url http string, auth dict, sgs list of names)
 -- delete list of ASGs'''
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    for del_sg in sgs:
        # get GUID first
        sg_r = s.get(base_url + "/v2/security_groups", verify=should_verify,
                     params={'q': "name:%s" % (del_sg)})
        if not sg_r.ok:
            raise ASGException('ASG name {0} lookup failed {1}'.format(
                del_sg, sg_r.url))
        sg_detail = sg_r.json()
        for r in sg_detail['resources']:
            # assume only one
            sgs_name = r['entity']['name']
            sgs_guid = r['metadata']['guid']
            message(args.json, 'deleted', {'name': sgs_name, 'guid': sgs_guid})
            # print("deleting %s / %s" % (sgs_name, sgs_guid))
            if enforcing:
                dr = s.delete(base_url + "/v2/security_groups/%s" % (sgs_guid),
                              verify=should_verify)
                if not dr.ok:
                    raise ASGException('delete_sgs {0} fails {1}'.format(
                        del_sg, dr.url))


def unbind_staging(enforcing, base_url, headers, ubs_sg):
    '''unbind_staging(base_url http string, auth dict, ubs_sg names) --
unbind default staging ASG'''
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    sg_r = s.get(base_url + "/v2/security_groups",
                 verify=should_verify,
                 params={'q': "name:%s" % (ubs_sg['name'])})
    if not sg_r.ok:
        raise ASGException('unbind_staging: error fetching ASG %s: %s' %
                           (ubs_sg['name'], sg_r.text))
    sg_detail = sg_r.json()
    for r in sg_detail['resources']:
        # assume only one?
        sgs_name = r['entity']['name']
        sgs_guid = r['metadata']['guid']
        message(args.json,
                'unbind_staging', {'name': sgs_name, 'guid': sgs_guid})
        # print("unbind_staging %s %s" % (sgs_name, sgs_guid))
        if enforcing:
            sg_r = s.delete(base_url + '/v2/config/staging_security_groups/%s' % (
                sgs_guid), verify=should_verify)
            if not sg_r.ok:
                raise ASGException('unbind_staging: error unbinding ASG %s: %s' %
                                   (ubs_sg['name'], sg_r.text))


def bind_staging(enforcing, base_url, headers, bs_sg):
    '''bind_staging(base_url http string, auth dict, bs_sg string sg name)
-- bind default staging ASG'''
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    sg_r = s.get(base_url + "/v2/security_groups",
                 verify=should_verify,
                 params={'q': "name:%s" % (bs_sg['name'])})
    if not sg_r.ok:
        raise ASGException('unbind_staging: error fetching ASG %s: %s' %
                           (bs_sg['name'], sg_r.text))
    sg_detail = sg_r.json()
    for r in sg_detail['resources']:
        sgs_name = r['entity']['name']
        sgs_guid = r['metadata']['guid']
        message(args.json,
                'bind_staging', {'name': sgs_name, 'guid': sgs_guid})
        # print("bind_staging %s %s" % (sgs_name, sgs_guid))
        if enforcing:
            sg_r = s.put(base_url + '/v2/config/staging_security_groups/%s' % (
                sgs_guid), verify=should_verify)
            if not sg_r.ok:
                raise ASGException('bind_staging: error binding ASG %s: %s' %
                                   (bs_sg['name'], sg_r.text))


def unbind_running(enforcing, base_url, headers, ubr_sg):
    '''unbind_running(base_url http string, auth dict, ubr_sg name) --
unbind default running ASG'''
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    sg_r = s.get(base_url + "/v2/security_groups",
                 verify=should_verify,
                 params={'q': "name:%s" % (ubr_sg['name'])})
    if not sg_r.ok:
        raise ASGException('unbind_running: error fetching ASG %s: %s' %
                           (ubr_sg['name'], sg_r.text))
    sg_detail = sg_r.json()
    for r in sg_detail['resources']:
        # assume only one?
        sgs_name = r['entity']['name']
        sgs_guid = r['metadata']['guid']
        message(args.json,
                'unbind_running', {'name': sgs_name, 'guid': sgs_guid})
        # print("unbind_running %s / %s" % (sgs_name, sgs_guid))
        if enforcing:
            sg_r = s.delete(base_url + "/v2/config/running_security_groups/%s" % (
                sgs_guid), verify=should_verify)
            if not sg_r.ok:
                raise ASGException('unbind_running: error unbinding ASG %s: %s' %
                                   (ubr_sg['name'], sg_r.text))


def bind_running(enforcing, base_url, headers, br_sg):
    '''bind_running(base_url http string, auth dict, br_sg name) --
bind default running ASG'''
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    sg_r = s.get(base_url + "/v2/security_groups",
                 verify=should_verify,
                 params={'q': "name:%s" % (br_sg['name'])})
    if not sg_r.ok:
        raise ASGException('unbind_running: error fetching ASG %s: %s' %
                           (br_sg['name'], sg_r.text))
    sg_detail = sg_r.json()
    for r in sg_detail['resources']:
        sgs_name = r['entity']['name']
        sgs_guid = r['metadata']['guid']
        message(args.json,
                'bind_running', {'name': sgs_name, 'guid': sgs_guid})
        # print("bind_running %s / %s" % (sgs_name, sgs_guid))
        if enforcing:
            sg_r = s.put(base_url + "/v2/config/running_security_groups/%s" % (
                sgs_guid), verify=should_verify)
            if not sg_r.ok:
                raise ASGException('bind_running: error binding ASG %s: %s' %
                                   (br_sg['name'], sg_r.text))


def add_file(filename):
    '''read a <group>.yml file for allowed security group.
    One security group per file.'''
    with open(filename, 'r') as f:
        new_sg = yaml.safe_load(f)
    # validate contents - we need a name
    if 'policy_name' not in new_sg:
        raise ASGException('no policy_name specified in file %s' % (filename))
    if 'running_default' in new_sg:
        running_default = new_sg['running_default']
    else:
        running_default = False
    if 'staging_default' in new_sg:
        staging_default = new_sg['staging_default']
    else:
        staging_default = False
    return {'name': new_sg['policy_name'],
            'running_default': running_default,
            'staging_default': staging_default}


# get list of security groups configured from command line
parser = argparse.ArgumentParser(
    prog='reconcile-asg',
    description='reconcile ASGs against inventory')
parser.add_argument('-d', '--delete',
                    action='store_true',
                    default=False,
                    help='delete incorrect security groups')
parser.add_argument('-D', '--debug',
                    action='store_true',
                    default=False,
                    help='enable debugging messages')
parser.add_argument('-j', '--json',
                    action='store_true',
                    default=False,
                    help='messages in json format')
parser.add_argument('file', nargs='*', help='list of files')
args = parser.parse_args()

# read in ASG configuration file the list of files
start = time.time()
configured_list = dict()
for file in args.file:
    new = add_file(file)
    configured_list[new['name']] = new
end = time.time()

if args.debug:
    print("valid_asgs (%.02fsec) %d entries: %s" % (
        (end - start), len(configured_list),
        json.dumps(configured_list, indent=2)))


# read in ASGs from the live environment
start = time.time()
actual_list = dict()
config = get_home()
auth_refresh = cf_refresh(config)
headers = {'Authorization':
           auth_refresh['token_type'] + ' ' + auth_refresh['access_token']}
actual_running_list = get_running_asgs(config['Target'], headers)
actual_staging_list = get_staging_asgs(config['Target'], headers)
end = time.time()
if args.debug:
    print("actual_asgs (%.02fsec) %d entries: %s\n%s" % (
        (end - start),
        len(actual_running_list) + len(actual_staging_list),
        json.dumps(actual_running_list, indent=2),
        json.dumps(actual_staging_list, indent=2)))

# compute the "diff" of the *names* of the configured versus actual config'd
# asgs -- and just delete them
start = time.time()
actual_list = dict(actual_running_list, **actual_staging_list)
delete_asg_names = list(set(actual_list.keys()) -
                        set(configured_list.keys()))
# delete security groups that shouldn't be there, use "args.delete"
# to determine whether to actually delete
auth_refresh = cf_refresh(config)
headers = {'Authorization': "%s %s" % (auth_refresh['token_type'],
                                       auth_refresh['access_token'])}
delete_sgs(args.delete, config['Target'], headers, delete_asg_names)

# remove deleted from list of names, so we dont keep scanning them
for d in delete_asg_names:
    del actual_list[d]

end = time.time()
if args.debug:
    print("delete ASG names (%.02fsec) %d entries" % (
        (end - start), len(delete_asg_names)))

# The names should all be legitimate now (for global lists), make sure
# that the bindings (staging, running, staging+running) is correct
start = time.time()
for cfgd_name in configured_list.keys():
    if args.debug:
        print("checking bindings for", cfgd_name)
    if configured_list[cfgd_name]['running_default'] is False and \
       cfgd_name in actual_running_list:
        unbind_running(args.delete, config['Target'], headers,
                       configured_list[cfgd_name])
    if configured_list[cfgd_name]['running_default'] is True and \
       cfgd_name not in actual_running_list:
        bind_running(args.delete, config['Target'], headers,
                     configured_list[cfgd_name])
    if configured_list[cfgd_name]['staging_default'] is False and \
       cfgd_name in actual_staging_list:
        unbind_staging(args.delete, config['Target'], headers,
                       configured_list[cfgd_name])
    if configured_list[cfgd_name]['staging_default'] is True and \
       cfgd_name not in actual_staging_list:
        bind_staging(args.delete, config['Target'], headers,
                     configured_list[cfgd_name])
end = time.time()
if args.debug:
    print("reconcile ASG bindings (%.02fsec) %d entries" % (
        (end - start), len(configured_list)))
dump_message(args.json, args.delete)
