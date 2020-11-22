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

reconcile-asgs validates the defined ASGs against the running/staging
global groups -- that is; if groups are defined as default-running or
default-staging, it will reconcile those against the listed ASG
definitions.

Note: it (currently) does not inspect the *rules* of the security
groups, only the names and whether it is globally bound for running or
staging time by default.

Note: it (currently) struggles with ASGs globally defined - but not
bound to runtime/staging-time at all.  If a group is defined, but not
assigned to either of these, this will not recognize it as something
that needs deleting.  (In order to detect these, reconcile-asgs would
have to enumerate all the security groups on the system, looking for
ones with no runtime/stagetime/org-space associations; this
could/would be prohibitively expensive on a large system with many
groups).

## Syntax
```
python reconcile-asgs.py [-D debug] [-d do deletes] [list of yaml files]
```
* The -D debug flag prints the list of names at each stage
* The -d delete flag indicates deletion is desirable

## pre-conditions for running
1. you are logged into a cloud foundry foundation
2. you are attached to an org/space
3. you give it a list of security group definitions

## file formats
### ASG YAML files
The YAML defines a list of ASGs (that contain appropriate data to
define the security groups).  The best example is in
tests/group-1.yaml, but just defines a list of name/rules sets.

## directory tests
Tests contains a series of security group definitions that are "valid"
-- i.e. these serve as inventory against which to reconcile the
existing environment.

## directory data
Data for tests -- running the test-create-sgs.sh script will populate
sample data against which you may test.

## Example Usage
The requirements.txt contains dependent packages -- this may be used
inside of a virtual environment for testing.

The below will delete any ASGs not defined in the tests yaml files
```
% python reconcile-asgs.py -d tests/*
```

The below will do a "dry run" - indicating which ASGs would be deleted
```
% python reconcile-asgs.py -D tests/*
```

## Example Testing
A testing script (test-create-sgs.sh) will create a set of semi-bogus
security groups which can then be "reconciled".  The script attempts
to cover valid use-cases.  It creates all the tests/test-*.yaml
security groups (and modifies a few), so reconcile-asgs can be used to
update/reconcile all those new groups.
