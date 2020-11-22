#!/bin/bash
#
## Generate a set of test security groups for reconcile_asgs.py to run
## against.
##
## Cautions:
## This depends on tests/*yaml files being in place - see ASSUME
## This runs with test-verify-asgs.sh
##
## There are a lot of combinations to cover here:
## 1) verify that only declared ASGs are stage/run bound
## 2) verify that declared ASGs have correct stage/run bindings
## Do NOT delete ASGs associated with an org/space
##
#

# test org/space to bind against
TESTORG="cfdev-org"
TESTSPACE="cfdev-space"

# generate data for random security groups
echo '[{"description": "allow stuff", "destination": "10.0.11.0/24", "ports": "80,443", "protocol": "tcp"}]' > /tmp/confusing-asg.json

# create a globally-bound security group for runtime
cf create-security-group foobar /tmp/confusing-asg.json
cf bind-running-security-group foobar
# this should be deleted after a reconcile run

# create a global security group that isn't bound to anything
cf create-security-group test-98-group-98 /tmp/confusing-asg.json
# this should be deleted after a reconcile run

# create all test groups
rm -rf /tmp/json
mkdir /tmp/json
for file in tests/test-*
do
    fname=${file%%.*}
    fname=${fname##*/}
    echo creating json for $fname
    cat $file | python -c 'import sys, yaml, json; print(json.dumps(yaml.load(sys.stdin, Loader=yaml.FullLoader)))' > /tmp/json/$fname.json
done

for json in /tmp/json/*
do
    asg_name=$(jq -r .policy_name $json)
    running_default=$(jq -r .running_default $json | tr '[A-Z]' '[a-z]')
    staging_default=$(jq -r .staging_default $json | tr '[A-Z]' '[a-z]')
    rules=$(jq -c -r .rules $json)
    echo "$rules" > /tmp/now.json
    echo creating asg $asg_name
    cf create-security-group $asg_name /tmp/now.json
    if [ "${running_default}" = "true" ];
    then
	echo binding running globally
	cf bind-running-security-group $asg_name
    fi
    if [ "${staging_default}" = "true" ];
    then
	echo binding staging globally
	cf bind-staging-security-group $asg_name
    fi
done
# any test group that isn't included in the reconcile list should be deleted

# test removing extra running binding
cf bind-running-security-group test-3-group-1   # globally bind it running
# this should be set back to not running-bound

# test remove extra staging binding
cf bind-staging-security-group test-3-group-2   # globally bind it staging
# this should be set back to not staging-bound

# test that a security group bound to an org/space is left alone
cf bind-security-group test-3-group-1 $TESTORG $TESTSPACE # bind to a space
# this should be left in place

# test missing running binding
cf unbind-running-security-group test-3-group-3
# this should be re-bound for running

# test missing staging binding
cf unbind-staging-security-group test-3-group-4
# this should be re-bound for staging
