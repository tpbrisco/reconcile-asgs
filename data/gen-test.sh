
# create global running security group "test1"
cf create-security-group test1 test1.json
cf bind-running-security-group test1

# create global staging security group "test2"
cf create-security-group test2 test2.json
cf bind-staging-security-group test2

# create unbound group
cf create-security-group test3 test3.json
