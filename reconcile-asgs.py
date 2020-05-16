#!/usr/bin/env python3
#
# reconcile-asgs.py [list of yaml]
# outputs: list of security groups in the foundation that are not named
# in the [list of yaml] files.
#
# reconcile-asgs is an aid in managing application security groups in
# cloud foundry.  As security groups are added/deleted/changed over
# time, it is simple for configuration drift to occur.
#
# Reconcile the security groups listed in the yaml files against the
# security groups in a running foundation.  Lists the security groups
# in the foundation that are not indicated in the YAML files.  These
# are security groups that could/should be deleted.
#

import os
import sys
import requests
import json
import yaml
import argparse
import time


class ASGException(Exception):
    def __init__(self, message):
        super().__init__(message)


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
                            verify=False)
    if not oauth_r.ok:
        print("error in token refresh:", oauth_r.json()['error_description'],
              file=sys.stderr)
        os.exit(1)
    return oauth_r.json()


# for debugging, export PYTHONWARNINGS="ignore:Unverified HTTPS request"
should_verify = False


def get_sgs(base_url, headers):
    '''get_sgs(base_url http string, auth dict) - return list of ASGs'''
    sgs = list()  # empty list of security groups
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json',
                      'Accept': 'application/json'})
    s.headers.update(headers)
    r = s.get(base_url + "/v2/security_groups", verify=should_verify)
    next_page = True
    while (next_page):
        next_page = False
        sgs_r = r.json()
        for res in sgs_r['resources']:
            sgs.append(res['entity']['name'])
        if sgs_r['next_url']:
            r = s.get(sgs_r['next_url'])
            next_page = True
    return sgs


allowed_asgs = list()

def add_file(filename):
    '''read a <group>.json file for allowed security group'''
    new_sg_list = list()
    sg_return = list()
    with open(filename, 'r') as f:
        new_sg_list = yaml.safe_load(f)
    # validate contents - we need a name
    for asg in new_sg_list:
        if 'name' not in asg:
            raise ASGException('no \'name\' specified in file %s' % (filename))
        sg_return.append(asg['name'])
    return sg_return


# get list of security groups configured from command line
parser = argparse.ArgumentParser()
parser.add_argument('file', nargs='*')
args = parser.parse_args()

# read in ASG configuration file the list of files
start = time.time()
configured_list = list()
for file in args.file:
    configured_list = configured_list + add_file(file)
end = time.time()
print("valid_asgs (%.02fsec): %s" % (
    (end - start), json.dumps(configured_list, indent=2)))


# read in ASG from the live environment
start = time.time()
actual_list = list()
config = get_home()
auth_refresh = cf_refresh(config)
headers = {'Authorization': auth_refresh['token_type'] + ' ' + auth_refresh['access_token']}
actual_list = get_sgs(config['Target'], headers)
end = time.time()
print("actual_asgs (%.02fsec): %s" % (
    (end - start), json.dumps(actual_list, indent=2)))

# compute the "diff" between the "allowed_asgs" and "actual_asgs" -- traverse
# allowed_asgs, and delete it from actual_asgs -- this should yield a list
# of ASGs that need to be removed (in actual_asgs).

delete_asgs = list(set(actual_list) - set(configured_list))
print("to delete:", json.dumps(delete_asgs, indent=2))