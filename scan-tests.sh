#/usr/bin/env bash
#
#
# test for scan-asgs.py -- this exercises various parts of the "policy
# scan" for cloud foundry.  This assumes the default Pivotal security
# groups are installed -- these are "all_access" and
# "default_security_group".
#
set -e
#

PY=python3
TD=$(mktemp -d)

# check to make sure security groups exist
all_access=$(cf curl '/v2/security_groups?q=name:all_access' | jq .total_results)
[ ${all_access} != "1" ] &&
    echo 'all_access security group not there?' && exit 1
all_access=$(cf curl '/v2/security_groups?q=name:default_security_group' | jq .total_results)
[ ${all_access} != "1" ] &&
    echo 'default_security_group security group not there?' && exit 1

# check for network masks less than a /22
${PY} scan-asgs.py -D -m 22 > ${TD}/base-scan.txt
[ -z "$(grep ^default_security_group ${TD}/base-scan.txt)" ] &&
    echo 'Missed /22 violation for default_security_group'
[ -z "$(grep ^all_access ${TD}/base-scan.txt)" ] &&
    echo 'Missed /22 violation for all_access'
rm -f ${TD}/base-scan.txt

# check for prohibited network
${PY} scan-asgs.py -D -m 0 -n 172.17.0.0/16 > ${TD}/net-scan.txt
[ -z "$(grep ^default_security_group ${TD}/net-scan.txt)" ] &&
    echo 'Missed 172.17/16 prohibited network for default_security_group'
[ -z "$(grep ^all_access ${TD}/net-scan.txt)" ] &&
    echo 'Missed 172.17/16 prohibited network for all_access'
rm -f ${TD}/net-scan.txt

# check for omitting a security group from policy
${PY} scan-asgs.py -D -m 22 -n 172.17.0.0/16 -s all_access -s default_security_group > ${TD}/skip-scan.txt
[ ! -z "$(grep ^default_security_group ${TD}/skip-scan.txt)" ] &&
    echo 'Missed omitting default_security_group from checks'
[ ! -z "$(grep ^all_access ${TD}/skip-scan.txt)" ] &&
    echo 'Missed omitting all_access from checks'
rm -f ${TD}/skip-scan.txt

# check for omitting groups by regular expression
${PY} scan-asgs.py -D -m 22 -n 172.17.0.0/16 -r 'all.*' -r 'default.*' > ${TD}/skip-re.txt
[ ! -z "$(grep ^default_security_group ${TD}/skip-re.txt)" ] &&
    echo 'Missed omitting default_security_group from checks'
[ ! -z "$(grep ^all_access ${TD}/skip-re.txt)" ] &&
    echo 'Missed omitting all_access from checks'
rm -f ${TD}/skip-re.txt

rm -rf ${TD}
