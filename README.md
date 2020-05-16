# reconcile-asgs

reconcile-asgs is an aid in effectively managing security groups in
Cloud Foundry.

As ASGs are added/removed/changed over time, it is possible for drift
to occur.  E.g. a common error is for someone to remove a definition
of an ASG, but forget to remove it from the environment.

reconcile-asgs takes a list of valid ASG definitions, inspects an
attached org/space, and prints a list of ASGs that exist that are not
in the defined list of valid ASGs.  I.e. it "diffs" between the
intended state (the list of ASGs from the YAML files) and the running
environment.

Note: it (currently) does not inspect the *content* of the security
groups, only the names.

## pre-conditions for running
1. you are logged into a cloud foundry foundation
2. you are attached to an org/space
3. you give it a list of security group definitions

## file formats
### ASG YAML files
The YAML defines a list of ASGs (that contain appropriate data to
define the security groups).  The best example is in
tests/group-1.yaml, but just defines a list of name/rules sets.

