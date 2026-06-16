#!/bin/bash

#####
## Build Environment Setup
#####
java17_0

#####
## Execute Dependency Scanning
#####

dependency_scan --configuration-matching='^(release|debug)(Compile|Runtime)Classpath$'
