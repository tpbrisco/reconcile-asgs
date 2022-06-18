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
cf create-security-group foobar /tmp/confusing-asg.json > /dev/null
cf bind-running-security-group foobar > /dev/null
# this should be deleted after a reconcile run
echo created foobar, globally running

# create a global security group that isn't bound to anything
cf create-security-group test-98-group-98 /tmp/confusing-asg.json > /dev/null
# this should be deleted after a reconcile run
echo created test-98-group-98, not bound to anything

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
    cf create-security-group $asg_name /tmp/now.json > /dev/null
    if [ "${running_default}" = "true" ];
    then
	echo binding running globally
	cf bind-running-security-group $asg_name > /dev/null
    fi
    if [ "${staging_default}" = "true" ];
    then
	echo binding staging globally
	cf bind-staging-security-group $asg_name > /dev/null
    fi
done
# any test group that isn't included in the reconcile list should be deleted

# test removing extra running binding
cf bind-running-security-group test-3-group-1 > /dev/null  # globally bind it running
# this should be set back to not running-bound
python reconcile-asgs.py --json --delete tests/*.yaml cf-default-sgs/*.yml > /tmp/remediation.json
found=$(jq -M '.data |has("unbind_running")' /tmp/remediation.json)  # did we find it?
[[ $found != "true" ]] &&
    echo "reconcile should have found 'unbind_staging' : test-3-group-1" &&
    exit 1
name=$(jq -Mr '.data.unbind_running.groups[] |select(.name=="test-3-group-1") |.name' /tmp/remediation.json)
[[ $name != "test-3-group-1" ]] &&
    echo "reconcile should have found 'unbind running' for test-3-group-1" &&
    exit 1
echo "test-3-group-1 rebound to initial state"

# test remove extra staging binding
cf bind-staging-security-group test-3-group-2 > /dev/null  # globally bind it staging
# this should be set back to not staging-bound
python reconcile-asgs.py --json --delete tests/*.yaml cf-default-sgs/*.yml > /tmp/remediation.json
found=$(jq -M '.data |has("unbind_staging")' /tmp/remediation.json) # did we find it?
[[ $found != "true" ]] &&
    echo "reconcile should have found 'unbind_staging' : test-3-group-2" &&
    exit 1
name=$(jq -Mr '.data.unbind_staging.groups[] |select(.name=="test-3-group-2") |.name' /tmp/remediation.json)
[[ $name != "test-3-group-2" ]] &&
    echo "reconcile should have found 'unbind_staging' for test-3-group-2" &&
    exit 1
echo "test-3-group-2 rebound to initial state"

# test that a security group bound to an org/space is left alone
cf bind-security-group test-3-group-1 $TESTORG $TESTSPACE > /dev/null
# this should be left in place, and unchanged
python reconcile-asgs.py --json --delete tests/*.yaml cf-default-sgs/*.yml > /tmp/remediation.json
found=$(jq -Mr '.data |keys' /tmp/remediation.json)
[[ $found != "[]" ]] &&
    echo "reconcile should have done nothing to test-3-group-1" &&
    exit 1
echo "test-3-group-1 not modified, bound to $TESTORG $TESTSPACE"
cf unbind-security-group test-3-group-1 $TESTORG $TESTSPACE > /dev/null

# test missing running binding
cf unbind-running-security-group test-3-group-3 > /dev/null
# this should be re-bound for running
python reconcile-asgs.py --json --delete tests/*.yaml cf-default-sgs/*.yml > /tmp/remediation.json
found=$(jq -M '.data |has("bind_running")' /tmp/remediation.json) # did we find it?
[[ $found != "true" ]] &&
    echo "reconcile should have found missing 'bind_running': test-3-group-3" &&
    exit 1
name=$(jq -Mr '.data.bind_running.groups[] |select(.name=="test-3-group-3") |.name' /tmp/remediation.json)
[[ $name != "test-3-group-3" ]] &&
    echo "reconcile should have changed 'bind_running' for test-3-group-3" &&
    exit 1

# test missing staging binding
cf unbind-staging-security-group test-3-group-4 > /dev/null
# this should be re-bound for staging
python reconcile-asgs.py --json --delete tests/*.yaml cf-default-sgs/*.yml > /tmp/remediation.json
found=$(jq -M '.data |has("bind_staging")' /tmp/remediation.json) # did we find it?
[[ $found != "true" ]] &&
    echo "reconcile should have found 'bind_staging': test-3-group-4" &&
    exit 1
name=$(jq -Mr '.data.bind_staging.groups[] |select(.name=="test-3-group-4") |.name' /tmp/remediation.json)
[[ $name != "test-3-group-4" ]] &&
    echo "reconcile should have found 'bind_staging' for test-3-group-4" &&
    exit 1

echo all tests passed, cleaning up
python reconcile-asgs.py --json --delete cf-default-sgs/*.yml > /tmp/remediation.json

echo finishing final state cleanup
cf delete-security-group test-3-group-1 -f > /dev/null
cf delete-security-group test-3-group-2 -f > /dev/null
cf delete-security-group test-98-group-98 -f > /dev/null
