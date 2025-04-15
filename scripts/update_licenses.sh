#!/bin/bash

set -x

export GOFLAGS="-tags=debug,imagetrust,lint,metrics,mgmt,profile,scrub,search,sync,ui,userprefs"
echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md
echo "---|---|---" >> THIRD-PARTY-LICENSES.md;

go list -m all | awk '{print $1}' | xargs -P20 -n1 nice -n 15 go-licenses csv 2>/dev/null | awk -F, '{print $1"|"$2"|"$3}' | LC_ALL=C sort -u >> THIRD-PARTY-LICENSES.md
