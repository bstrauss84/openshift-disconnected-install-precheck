# Greg's Idea

Main idea to make a utility using Quarkus (in command line mode) to implement a system for scanning an environment based on a specified ruleset.
Each rule would be read in and checked for, and added to a nicely formatted report at the end.


The ruleset could be sourced locally, or be pulled from a URL.

TODOs:

 - how to specify that hosts don't exist yet, but allow for determining if a virtualized environment has the juice to provision them

## Utility deployment

Given we are leveraging Quarkus as the framework to build this utility, we actually have a choice on how to get it to the end user.
Quarkus supports either running the packaged app as either a regular Java app, or using GraalVM to take that Java bytecode and fully compiling down to a native executable.

Source would of course be available, but we can wrap up everything needed by the app into one file with minimal external dependencies (just what is needed to run the rules).
The packaged utility can have its code and supply chain scanned at every step, and result signed to be certified by RH.

Could either use the host the utility is run from, or use SSH as a proxy to run commands.



## Run Configuration and Rules

```yaml
wib:
  # Where shell commands should be run for general environmental checks.
  runner:
    type: self|external
    # if external...
    host: 
    # ... other connectivity fields
  # If any, hosts that should be connected to and are to be considered part of the install, i.e, are available to have things installed on them
  hosts:
    - type: self
    - type: remote
      tags:
        - worker
      host: workera.acme.com
      # more connection info. user, ssl cert location, maybe but probably not password, ssh options?
  rules:
    # define a rule in here (simple usecases)
    - type: explicit
      rule:
        # Rule
    # example using an external url 
    - type: ruleset
      source: https://github.com/ocp4base.yaml
    # example using a local file
    - type: ruleset
      source: ocp4disconnected.yaml
    # example using a local zipped file (zip and/or tar)
    # each yaml file in the bundle would be read in and processed like the standard ruleset file.
    - type: ruleset
      source: ocp4bundle.zip
```

### Rules

#### In general

```yaml
type: <type label>
title: <the title to use to display this rule in outputs and reports>
description: <description of this particular rule to show in outputs and reports>
footprint: <describing what this rule means and why it is important. new name?>
furtherReading:
  - title: <title of link>
    url: <link to send user to>
# How important this rule is to be adhered to
severity: required|recommended|future
hosts:
  - <entry from "host filtering" section>
```

##### Host Filtering

To run on runner:

```yaml
type: runner
```

To run on each host (besides runner):

```yaml
type: all
```

To run on all hosts with given tag:

```yaml
type: tag
tag: <tag>
```

#### Concerning Connectivity

##### Ping

```yaml
type: ping
host: <host to ping, not a host in our hosts list>
```

##### simple REST call

```yaml
type: web_call
url: <url to send a GET request to>
status: <defaults to 200>
# More check besides status?
```

##### DNS

##### Network I/O

#### Concerning Host

##### Number of hosts

Allows you to specify number of hosts that should exist.

```yaml
type: num-hosts
number: <number of hosts to expect given the filters>
```

##### OS

OS make, version. Kernel version?

##### Disk space/ usage

```yaml
type: disk_space
dirToTest: <where to check, default "/", in order to test different partition mounted locations>
freeSpace: <human readable format, like "5MB" or similar>
```

##### Disk I/O test

##### Installed packages/ version

##### File existence/ contents?

##### 

#### Generic

```yaml
type: generic
# TODO:: host specifier? default runner
command:
  - command
  - args
  - to
  - run
verification:
  returns: <code, default 0>
  outputs:
    stdout:
      - <regex to check the std out for>
    stderr:
      - <regex to check the std err for>
  # others, maybe additional check script
```

## Reports

Reports would be able to be generated into several formats:

 - stdout
 - textfile
 - Markdown
 - PDF

Stretch goal formats:

 - asciidoc
 - word?
 - xml/ods
 - html

Given we have a notion of rule severity (required|recommended|future), we can first organize the outputs by, if they failed, by what severity that failing rule would have.
Additionally, if no hosts specified, it should be upfront to explain the rules that each future exiestent host should abide by.

