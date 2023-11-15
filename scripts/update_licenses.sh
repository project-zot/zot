#!/bin/bash

set -x

export GOFLAGS="-tags=debug,imagetrust,lint,metrics,mgmt,profile,scrub,search,sync,ui,userprefs,containers_image_openpgp"
echo "Module | License URL | License" > THIRD-PARTY-LICENSES.md
echo "---|---|---" >> THIRD-PARTY-LICENSES.md;

for i in $(go list -m all  | awk '{print $1}'); do
    l=$(go-licenses csv $i 2>/dev/null)
    if [ $? -ne 0 ]; then continue; fi
    echo $l | tr \, \| | tr ' ' '\n'
done | LC_ALL=C sort -u >> THIRD-PARTY-LICENSES.md