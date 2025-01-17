#!/bin/sh -xe

# enable user namespaces
sysctl -w kernel.apparmor_restrict_unprivileged_io_uring=0
sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
sysctl -w kernel.apparmor_restrict_unprivileged_userns_complain=0
sysctl -w kernel.apparmor_restrict_unprivileged_userns_force=0
sysctl -w kernel.unprivileged_bpf_disabled=2
sysctl -w kernel.unprivileged_userns_apparmor_policy=0
sysctl -w kernel.unprivileged_userns_clone=1
