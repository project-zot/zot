#!/usr/bin/env bash
# Tests for install/linux/zotctl. Runs unprivileged against a scratch directory with a
# fake systemctl, fake zot/zli binaries and a fake htpasswd (bcrypt itself is
# not exercised). Usage: install/linux/zotctl_test.sh
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ZOTCTL="$HERE/zotctl"
T=$(mktemp -d "${TMPDIR:-/tmp}/zotctl-test.XXXXXX")
trap 'rm -rf "$T"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
check() { # description command...
    local d=$1; shift
    if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
section() { printf '\n== %s\n' "$1"; }

# ------------------------------------------------------------------ fixtures --
mkdir -p "$T/fakebin" "$T/state"
cat >"$T/fakebin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_STATE/calls"
cmd=$1; shift
case $cmd in
    is-active)
        quiet=0; [ "${1:-}" = --quiet ] && { quiet=1; shift; }
        if [ -e "$FAKE_STATE/$1.activating" ]; then [ $quiet = 1 ] || echo activating; exit 3; fi
        if [ -e "$FAKE_STATE/$1.active" ]; then [ $quiet = 1 ] || echo active; exit 0; fi
        [ $quiet = 1 ] || echo inactive; exit 3 ;;
    start) touch "$FAKE_STATE/$1.active" ;;
    stop) rm -f "$FAKE_STATE/$1.active" ;;
    restart) touch "$FAKE_STATE/$1.active" ;;
    enable|disable)
        now=0; for a in "$@"; do [ "$a" = --now ] && now=1; done
        for a in "$@"; do case $a in -*) ;; *) if [ $now = 1 ]; then
            if [ "$cmd" = enable ]; then touch "$FAKE_STATE/$a.active"; else rm -f "$FAKE_STATE/$a.active"; fi; fi ;; esac; done ;;
    show) case "$*" in
        *MainPID*) echo 0 ;;
        *ActiveEnterTimestamp*) if [ -e "$FAKE_STATE/started.old" ]; then echo "Sat 2000-01-01 00:00:00 UTC"; else date; fi ;;
        *) echo ;; esac ;;
esac
exit 0
EOF
chmod +x "$T/fakebin/systemctl"

cat >"$T/fakebin/htpasswd" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_STATE/htpasswd.argv"
create=0; del=0
while [ $# -gt 0 ]; do case $1 in -B|-i|-b) ;; -c) create=1 ;; -D) del=1 ;; *) break ;; esac; shift; done
file=$1; user=$2
tmp=$(mktemp "$file.fake.XXXXXX")
[ $create = 1 ] && : >"$file"
awk -F: -v u="$user" '$1 != u' "$file" >"$tmp" || true   # exact match, like the real tool
if [ $del = 0 ]; then read -r pw; echo "$user:\$2y\$05\$$(printf %s "$pw" | sha256sum | cut -c1-53)" >>"$tmp"; fi
cat "$tmp" >"$file"; rm -f "$tmp"   # in place, like the real tool (keeps mode/owner)
EOF
chmod +x "$T/fakebin/htpasswd"

# stand-in for runuser: refuses any argument listed in $DENY_FILE (simulates the service user lacking access)
cat >"$T/fakebin/asuser" <<'EOF'
#!/usr/bin/env bash
echo "$ZOTCTL_SERVICE_USER" >>"${FAKE_STATE:-/tmp}/asuser.log"
if [ -f "${DENY_FILE:-/nonexistent}" ]; then
    for a in "$@"; do grep -qxF "$a" "$DENY_FILE" && exit 1; done
fi
exec "$@"
EOF
chmod +x "$T/fakebin/asuser"

cat >"$T/os-release" <<'EOF'
ID=ubuntu
ID_LIKE=debian
EOF

make_bin() { # path commit [bad]
    {
        printf '#!/usr/bin/env bash\n'
        [ -n "${3:-}" ] && printf '#BAD\n'
        [ "${NOTIFY:-1}" = 1 ] && printf '#READY=1\n'
        [ "${HC:-1}" = 1 ] && printf '#startupz\n'
        cat <<EOF
case "\$1" in
  --version|-v) echo '{"level":"info","message":"version","commit":"$2","binary-type":"-search-ui"}' ;;
  verify)
    # like the real zot: the log file is opened (and created), and a missing directory panics
    tr -d '\n' <"\$2" >>"\${FAKE_STATE:-/tmp}/verify.calls"; echo >>"\${FAKE_STATE:-/tmp}/verify.calls"
    out=\$(jq -r '.log.output // empty' "\$2")
    if [ -n "\$out" ] && [ ! -d "\$(dirname "\$out")" ]; then echo "panic: open \$out: no such file or directory" >&2; exit 2; fi
    exit 0 ;;
  healthcheck) echo "\$*" >>"\${FAKE_STATE:-/tmp}/healthcheck.calls"; [ -e "\${FAKE_STATE:-/nonexistent}/hc.fail" ] && exit 1; exit 0 ;;
esac
EOF
    } >"$1"
    chmod +x "$1"
}

make_src() { # dir commit [bad]
    mkdir -p "$1"; make_bin "$1/zot" "$2" "${3:-}"; make_bin "$1/zli" "$2"
}

write_config() { # file port auth(yes|no) [tls(yes)]
    local auth="" tls=""
    [ "$3" = yes ] && auth=",\"auth\":{\"htpasswd\":{\"path\":\"$T/data/.htpasswd\"}}"
    [ "${4:-}" = yes ] && tls=",\"tls\":{\"cert\":\"$T/tls/server.crt\",\"key\":\"$T/tls/server.key\"}"
    cat >"$1" <<EOF
{"distSpecVersion":"1.1.0","storage":{"rootDirectory":"$T/data/images"},
 "http":{"address":"127.0.0.1","port":"$2"$auth$tls},
 "log":{"level":"info","output":"$T/logs/system.log"}}
EOF
}

DEFAULT_HC='! grep -q "^#BAD" "$PREFIX/current/zot"'
# run zotctl against the scratch install
zc() {
    FAKE_STATE="$T/state" ZOTCTL_TEST=1 ZOTCTL_UNIT_DIR="$T/units" ZOTCTL_SYSTEMCTL="$T/fakebin/systemctl" \
    ZOTCTL_OS_RELEASE="$T/os-release" ZOTCTL_POLL_SECS=1 WAIT_SECS=${WAIT_SECS:-4} \
    ZOTCTL_HEALTH_CMD="${ZC_HEALTH_CMD-$DEFAULT_HC}" ZOTCTL_LOGROTATE_DIR="$T/logrotate.d" ZOTCTL_RUN_AS="$T/fakebin/asuser" DENY_FILE="$T/deny" \
    PATH="$T/fakebin:$PATH" \
    "$ZOTCTL" "$@" --prefix "$T/prefix" --bin-dir "$T/bin" --config-dir "$T/data"
}
rc_of() { "$@" >/dev/null 2>&1; echo $?; }
reset_scratch() {
    rm -rf "${T:?}/prefix" "${T:?}/bin" "${T:?}/units" "${T:?}/data" "${T:?}/logs" "${T:?}/logrotate.d" "${T:?}/state"/* "${T:?}/deny"
    mkdir -p "$T/units" "$T/bin" "$T/data" "$T/logrotate.d" "$T/tls"
}
cur() { basename "$(readlink "$T/prefix/current")"; }
# a running host always has the directory of its log file (zot cannot create it)
existing_host_dirs() { mkdir -p "$T/logs"; : >"$T/logs/system.log"; }

# ----------------------------------------------------------------- usage ----
section "usage errors"
[ "$(rc_of "$ZOTCTL")" = 2 ] && ok "no command -> 2" || bad "no command -> 2"
[ "$(rc_of "$ZOTCTL" bogus)" = 2 ] && ok "unknown command -> 2" || bad "unknown command -> 2"
[ "$(rc_of "$ZOTCTL" upgrade --dir /x --version v1)" = 2 ] && ok "--dir with --version -> 2" || bad "--dir with --version -> 2"
[ "$(rc_of "$ZOTCTL" install --password hunter22)" = 2 ] && ok "password on command line rejected" || bad "password on command line rejected"
[ "$(rc_of "$ZOTCTL" upgrade --variant bogus)" = 2 ] && ok "bad variant -> 2" || bad "bad variant -> 2"
[ "$(rc_of "$ZOTCTL" prune --keep abc)" = 2 ] && ok "non-numeric --keep -> 2" || bad "non-numeric --keep -> 2"
reset_scratch
write_config "$T/cfg.json" 8443 no
[ "$(rc_of zc install --dir "$T/none")" = 2 ] && ok "install without --config -> 2" || bad "install without --config -> 2"

# ---------------------------------------------------------- dependencies ----
section "dependency check"
mkdir -p "$T/tools"
for t in bash env install mv ln mktemp uname rm cp sha256sum sed awk grep head tr cut date dirname basename stat cat mkdir \
         chmod id df du find ls sleep readlink curl jq rmdir wc sort printf; do
    p=$(command -v "$t" 2>/dev/null) && [ -x "$p" ] && ln -sf "$p" "$T/tools/$t"
done
make_src "$T/src_a" v1.0.0-a
out=$(PATH="$T/tools" ZOTCTL_TEST=1 ZOTCTL_OS_RELEASE="$T/os-release" ZOTCTL_UNIT_DIR="$T/units" "$(command -v bash)" "$ZOTCTL" \
      install --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --prefix "$T/prefix" 2>&1); rc=$?
[ "$rc" = 3 ] && ok "missing htpasswd -> exit 3" || bad "missing htpasswd -> exit 3 (got $rc)"
case $out in *"htpasswd"*"apache2-utils"*) ok "message names the tool and the apt package" ;; *) bad "message names tool/package: $out" ;; esac
rm -f "$T/tools/jq"
out=$(PATH="$T/tools" ZOTCTL_TEST=1 ZOTCTL_OS_RELEASE="$T/os-release" ZOTCTL_UNIT_DIR="$T/units" "$(command -v bash)" "$ZOTCTL" \
      install --dir "$T/src_a" --config "$T/cfg.json" --prefix "$T/prefix" 2>&1); rc=$?
[ "$rc" = 3 ] && ok "missing jq -> exit 3" || bad "missing jq -> exit 3 (got $rc)"
case $out in *"sudo apt-get install -y"*jq*) ok "install command suggested" ;; *) bad "install command suggested: $out" ;; esac
case $out in *"Then re-run"*) ok "re-run hint present" ;; *) bad "re-run hint present" ;; esac
[ ! -e "$T/prefix" ] && ok "nothing created when dependencies are missing" || bad "nothing created when dependencies are missing"

# ---------------------------------------------------------- fresh install ----
section "fresh install (auth, links, unit)"
reset_scratch
write_config "$T/cfg.json" 8443 yes
make_src "$T/src_a" v1.0.0-a
printf 'correct-horse-battery\n' >"$T/pw"; chmod 600 "$T/pw"
chmod 644 "$T/pw"
[ "$(rc_of zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --password-file "$T/pw")" != 0 ] \
    && ok "password file with mode 644 rejected" || bad "password file with mode 644 rejected"
chmod 600 "$T/pw"
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --password-file "$T/pw" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "install succeeds" || { bad "install succeeds (rc=$rc)"; cat "$T/out.txt"; }
check "current points into releases/" test "$(readlink "$T/prefix/current")" = "releases/v1.0.0-a"
check "zot link into current" test "$(readlink "$T/bin/zot")" = "$T/prefix/current/zot"
check "zli link into current" test "$(readlink "$T/bin/zli")" = "$T/prefix/current/zli"
check "unit written with ExecStart" grep -q "^ExecStart=$T/bin/zot serve $T/data/config.json" "$T/units/zot.service"
check "port 8443: no bind capability in unit" bash -c "! grep -q AmbientCapabilities '$T/units/zot.service'"
check "notify-capable binary -> Type=notify" grep -q '^Type=notify' "$T/units/zot.service.d/zotctl-type.conf"
check "notify drop-in sets a start timeout" grep -q '^TimeoutStartSec=5min' "$T/units/zot.service.d/zotctl-type.conf"
check "checksums recorded" test -s "$T/prefix/releases/v1.0.0-a/SHA256SUMS"
check "config installed" test -f "$T/data/config.json"
check "htpasswd has bcrypt-style entry" grep -q '^admin:\$2y\$' "$T/data/.htpasswd"
check "new htpasswd mode 0640 (root-written, zot-readable)" test "$(stat -c %a "$T/data/.htpasswd")" = 640
check "password never in htpasswd argv" bash -c "! grep -q correct-horse '$T/state/htpasswd.argv'"
check "password not written anywhere under prefix/units/state" bash -c "! grep -rq correct-horse '$T/prefix' '$T/units' '$T/state'"
check "service started" test -e "$T/state/zot.service.active"
check "health timer enabled" test -e "$T/state/zot-health.timer.active"
check "config dir is root-owned 0755" test "$(stat -c %a "$T/data")" = 755
check "config.json mode 0640" test "$(stat -c %a "$T/data/config.json")" = 640
check "storage dir mode 0750" test "$(stat -c %a "$T/data/images")" = 750
check "log dir created" test -d "$T/logs"
check "log file created for the service account (0640)" test "$(stat -c %a "$T/logs/system.log")" = 640
check "hardening drop-in written" grep -q '^NoNewPrivileges=yes' "$T/units/zot.service.d/zotctl-hardening.conf"
check "ReadWritePaths derived from config" grep -q "^ReadWritePaths=.*$T/data/images" "$T/units/zot.service.d/zotctl-hardening.conf"
check "ReadWritePaths includes the log file" grep -q "^ReadWritePaths=.*$T/logs/system.log" "$T/units/zot.service.d/zotctl-hardening.conf"
check "ProtectSystem=strict" grep -q '^ProtectSystem=strict' "$T/units/zot.service.d/zotctl-hardening.conf"
check "logrotate config written" grep -q copytruncate "$T/logrotate.d/zot"
check "logrotate names the log file" grep -q "$T/logs/system.log" "$T/logrotate.d/zot"
check "logrotate never signals zot (SIGHUP stops it)" bash -c "! grep -v '^#' '$T/logrotate.d/zot' | grep -qiE 'postrotate|kill|hup'"
check "health script uses zot healthcheck when supported" grep -q 'healthcheck' "$T/prefix/zot-health.sh"
check "health script keeps a /v2/ fallback" grep -q '/v2/' "$T/prefix/zot-health.sh"
check "verify passes with the hardening drop-in" zc verify
check "install again refused" bash -c "[ \$(ZOTCTL_TEST=1 ZOTCTL_UNIT_DIR='$T/units' ZOTCTL_SYSTEMCTL='$T/fakebin/systemctl' '$ZOTCTL' install --yes --dir '$T/src_a' --config '$T/cfg.json' --prefix '$T/prefix' --bin-dir '$T/bin' --config-dir '$T/data' >/dev/null 2>&1; echo \$?) != 0 ]"

section "fresh install of a build without sd_notify"
reset_scratch
write_config "$T/cfg.json" 8443 no
NOTIFY=0 make_src "$T/src_old" v0.9.0-old
zc install --yes --dir "$T/src_old" --config "$T/cfg.json" >/dev/null 2>&1
check "no READY=1 -> Type=simple" grep -q '^Type=simple' "$T/units/zot.service.d/zotctl-type.conf"
check "no notify settings for it" bash -c "! grep -q NotifyAccess '$T/units/zot.service.d/zotctl-type.conf'"
reset_scratch
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --start-timeout 12min >/dev/null 2>&1
check "--start-timeout honoured" grep -q '^TimeoutStartSec=12min' "$T/units/zot.service.d/zotctl-type.conf"
zc uninstall --yes >/dev/null 2>&1
check "uninstall removes the type drop-in" test ! -e "$T/units/zot.service.d/zotctl-type.conf"

section "fresh install: privileged port gets ambient capability; no-tty without credentials fails"
reset_scratch
write_config "$T/cfg.json" 443 yes
[ "$(rc_of zc install --yes --dir "$T/src_a" --config "$T/cfg.json" </dev/null)" != 0 ] \
    && ok "auth config + no user source + no tty -> fails" || bad "auth config + no user source + no tty -> fails"
[ ! -e "$T/prefix/current" ] && ok "nothing installed after that failure" || bad "nothing installed after that failure"
ZOTCTL_PASSWORD='another-long-pass' zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user ops >/dev/null 2>&1
check "port 443: unit grants CAP_NET_BIND_SERVICE" grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE' "$T/units/zot.service"
check "port 443: bounding set restricted" grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$T/units/zot.service"
check "env password used, user created" grep -q '^ops:' "$T/data/.htpasswd"
check "password absent from argv log (env source)" bash -c "! grep -q another-long-pass '$T/state/htpasswd.argv'"

# --------------------------------------------------- upgrade from hand-made ----
section "upgrade migrates a hand-installed zot"
reset_scratch
write_config "$T/data/config.json" 443 no; existing_host_dirs
NOTIFY=0 make_bin "$T/bin/zot" legacy-0; NOTIFY=0 make_bin "$T/bin/zli" legacy-0
cat >"$T/units/zot.service" <<EOF
[Service]
ExecStart=$T/bin/zot serve $T/data/config.json
EOF
touch "$T/state/zot.service.active"
make_src "$T/src_b" v2.0.0-b; make_src "$T/src_c" v3.0.0-c; make_src "$T/src_d" v4.0.0-d
before=$(find "$T/bin" "$T/units" | sort | xargs ls -ld 2>/dev/null | md5sum)
zc upgrade --dry-run --dir "$T/src_b" >/dev/null 2>&1
after=$(find "$T/bin" "$T/units" | sort | xargs ls -ld 2>/dev/null | md5sum)
[ "$before" = "$after" ] && ok "--dry-run changes nothing" || bad "--dry-run changes nothing"
[ ! -e "$T/prefix/current" ] && ok "--dry-run did not create prefix/current" || bad "--dry-run did not create prefix/current"
zc upgrade --yes --dir "$T/src_b" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "upgrade succeeds" || { bad "upgrade succeeds (rc=$rc)"; cat "$T/out.txt"; }
legacy=$(basename "$(find "$T/prefix/releases" -maxdepth 1 -name 'legacy-*' | head -1)")
[ "$legacy" != "." ] && [ -n "$legacy" ] && ok "legacy release created" || bad "legacy release created"
check "old binaries preserved as a legacy release" test -x "$T/prefix/releases/$legacy/zot"
check "bin-dir zot is now a link" test -L "$T/bin/zot"
check "current is the new release" test "$(cur)" = v2.0.0-b
check "new release records what it replaced" test "$(cat "$T/prefix/releases/v2.0.0-b/.previous")" = "$legacy"
check "capability drop-in written for port 443" grep -q CAP_NET_BIND_SERVICE "$T/units/zot.service.d/zotctl.conf"
check "legacy (no READY=1) -> upgrade to notify build switches Type=notify" grep -q '^Type=notify' "$T/units/zot.service.d/zotctl-type.conf"
check "health timer not created for an existing install" test ! -e "$T/units/zot-health.timer"
zc upgrade --yes --dir "$T/src_c" >/dev/null 2>&1
check "second upgrade: current=C" test "$(cur)" = v3.0.0-c
check "C replaced B" test "$(cat "$T/prefix/releases/v3.0.0-c/.previous")" = v2.0.0-b
check "same release again -> exit 0, nothing to do" zc upgrade --yes --dir "$T/src_c"

section "rollback walks back through the history"
zc rollback --yes >/dev/null 2>&1; check "C -> B" test "$(cur)" = v2.0.0-b
zc rollback --yes >/dev/null 2>&1; check "B -> legacy" test "$(cur)" = "$legacy"
check "the legacy manifest does not hash itself" bash -c "! grep -q SHA256SUMS '$T/prefix/releases/$legacy/SHA256SUMS'"
check "verify passes on the migrated legacy release" zc verify
check "rollback to a non-notify binary switches to Type=simple" grep -q '^Type=simple' "$T/units/zot.service.d/zotctl-type.conf"
[ "$(rc_of zc rollback --yes)" != 0 ] && ok "legacy has no previous -> refuses" || bad "legacy has no previous -> refuses"
zc rollback --yes --to v3.0.0-c >/dev/null 2>&1; check "rollback --to goes forward" test "$(cur)" = v3.0.0-c
check "...and back to Type=notify" grep -q '^Type=notify' "$T/units/zot.service.d/zotctl-type.conf"
check "zot still running after rollbacks" test -e "$T/state/zot.service.active"

section "failed upgrade rolls back automatically"
make_src "$T/src_bad" v9.0.0-bad bad
WAIT_SECS=3 zc upgrade --yes --dir "$T/src_bad" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "failing release -> non-zero exit" || bad "failing release -> non-zero exit"
check "message says rolled back" grep -q "rolled back" "$T/out.txt"
check "still on v3.0.0-c" test "$(cur)" = v3.0.0-c
check "service running again" test -e "$T/state/zot.service.active"
check "failed release dir kept for inspection" test -d "$T/prefix/releases/v9.0.0-bad"

section "prune"
zc upgrade --yes --dir "$T/src_d" >/dev/null 2>&1
prev=$(cat "$T/prefix/releases/v4.0.0-d/.previous")
check "list shows releases" bash -c "$(declare -f zc) ; T='$T'; ZOTCTL='$ZOTCTL'; zc releases | grep -q v4.0.0-d"
[ "$(rc_of zc prune --yes --release v4.0.0-d)" != 0 ] && ok "current release cannot be pruned" || bad "current release cannot be pruned"
[ "$(rc_of zc prune --yes --release "$prev")" != 0 ] && ok "release rollback needs cannot be pruned" || bad "release rollback needs cannot be pruned"
n_before=$(ls "$T/prefix/releases" | wc -l)
zc prune --dry-run --keep 1 >/dev/null 2>&1
check "--dry-run prune deletes nothing" test "$(ls "$T/prefix/releases" | wc -l)" = "$n_before"
zc prune --yes --keep 1 >/dev/null 2>&1
check "current survives prune --keep 1" test -d "$T/prefix/releases/v4.0.0-d"
check "previous survives prune --keep 1" test -d "$T/prefix/releases/$prev"
check "legacy kept without --include-legacy" test -d "$T/prefix/releases/$legacy"
check "older releases removed" test ! -d "$T/prefix/releases/v2.0.0-b"
zc prune --yes --keep 1 --include-legacy >/dev/null 2>&1
check "legacy removed with --include-legacy" test ! -d "$T/prefix/releases/$legacy"
check "rollback to a pruned release explains itself" bash -c "$(declare -f zc rc_of); T='$T'; ZOTCTL='$ZOTCTL'; zc rollback --yes --to v2.0.0-b 2>&1 | grep -q 'no longer exists'"

# ------------------------------------------------------------ GitHub path ----
section "GitHub-style download (local file:// mirror)"
arch=$(uname -m); case $arch in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
mk_release() { # tag commit [corrupt]
    local d="$T/gh/$1"; mkdir -p "$d"
    make_bin "$d/zot-linux-$arch" "$2"; make_bin "$d/zli-linux-$arch" "$2"
    (cd "$d" && sha256sum "zot-linux-$arch" "zli-linux-$arch" | sed 's/  / */' >checksums.sha256.txt)
    if [ -n "${3:-}" ]; then echo "tampered" >>"$d/zot-linux-$arch"; fi
    make_bin "$d/zot-linux-$arch-minimal" "$2-minimal"
    (cd "$d" && sha256sum "zot-linux-$arch-minimal" | sed 's/  / */' >>checksums.sha256.txt)
}
mk_release v5.0.0 v5.0.0
export ZOTCTL_DOWNLOAD_BASE="file://$T/gh"
zc upgrade --yes --version v5.0.0 >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "upgrade from release tag succeeds" || { bad "upgrade from release tag (rc=$rc)"; cat "$T/out.txt"; }
check "release id is the tag" test "$(cur)" = v5.0.0
mk_release v5.0.1 v5.0.1 corrupt
zc upgrade --yes --version v5.0.1 >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "tampered download -> failure" || bad "tampered download -> failure"
check "reports checksum mismatch" grep -q "CHECKSUM MISMATCH" "$T/out.txt"
check "tampered release was not staged" test ! -d "$T/prefix/releases/v5.0.1"
check "still on v5.0.0" test "$(cur)" = v5.0.0
mk_release v5.0.2 v5.0.2
grep -v "zli-linux" "$T/gh/v5.0.2/checksums.sha256.txt" >"$T/gh/v5.0.2/c.tmp"; mv "$T/gh/v5.0.2/c.tmp" "$T/gh/v5.0.2/checksums.sha256.txt"
[ "$(rc_of zc upgrade --yes --version v5.0.2)" != 0 ] && ok "missing checksum entry -> failure" || bad "missing checksum entry -> failure"
[ "$(rc_of zc upgrade --yes --version v7.7.7)" != 0 ] && ok "nonexistent tag -> failure" || bad "nonexistent tag -> failure"
zc upgrade --yes --version v5.0.0 --variant minimal >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "same tag, different variant is a new upgrade" || { bad "variant upgrade (rc=$rc)"; cat "$T/out.txt"; }
check "the variant gets its own release id" test "$(cur)" = v5.0.0-minimal
check "extended and minimal releases are both kept" test -d "$T/prefix/releases/v5.0.0"
zc upgrade --yes --version v5.0.0 --variant minimal >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && grep -q "nothing to do" "$T/out.txt" && ok "same tag and variant again -> nothing to do" || bad "same tag and variant again -> nothing to do"
zc upgrade --yes --version v5.0.0 >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && grep -q "already installed" "$T/out.txt" && ok "switching back to an installed release points at rollback" || bad "switching back to an installed release points at rollback"
unset ZOTCTL_DOWNLOAD_BASE

# --------------------------------------------------------- users, verify ----
section "user management, verify, status"
reset_scratch
write_config "$T/cfg.json" 8443 yes
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --password-file "$T/pw" >/dev/null 2>&1
printf 'second-user-pass\n' >"$T/pw2"; chmod 600 "$T/pw2"
zc user add reader --password-file "$T/pw2" >/dev/null 2>&1
check "user add" grep -q '^reader:' "$T/data/.htpasswd"
[ "$(rc_of zc user add reader --password-file "$T/pw2")" != 0 ] && ok "duplicate user rejected" || bad "duplicate user rejected"
[ "$(rc_of zc user add 'bad:name' --password-file "$T/pw2")" != 0 ] && ok "invalid username rejected" || bad "invalid username rejected"
printf 'short\n' >"$T/pw3"; chmod 600 "$T/pw3"
[ "$(rc_of zc user passwd reader --password-file "$T/pw3")" != 0 ] && ok "short password rejected" || bad "short password rejected"
before=$(grep '^reader:' "$T/data/.htpasswd")
zc user passwd reader --password-file "$T/pw3" >/dev/null 2>&1
check "rejected change left the hash alone" test "$(grep '^reader:' "$T/data/.htpasswd")" = "$before"
check "user list shows both" bash -c "$(declare -f zc); T='$T'; ZOTCTL='$ZOTCTL'; test \"\$(zc user list | sort | tr '\n' ' ')\" = 'admin reader '"
zc user remove reader --yes >/dev/null 2>&1
check "user remove" bash -c "! grep -q '^reader:' '$T/data/.htpasswd'"
check "htpasswd mode unchanged after user changes" test "$(stat -c %a "$T/data/.htpasswd")" = 640
check "password never on htpasswd argv" bash -c "! grep -qE 'second-user-pass|short' '$T/state/htpasswd.argv'"
check "verify passes on a healthy install" zc verify
echo tamper >>"$T/prefix/releases/v1.0.0-a/zot"
[ "$(rc_of zc verify)" != 0 ] && ok "verify detects a modified binary" || bad "verify detects a modified binary"
check "status runs" zc status
check "config path" test "$(zc config path)" = "$T/data/config.json"
check "config show redacts secrets" bash -c "$(declare -f zc); T='$T'; ZOTCTL='$ZOTCTL'; echo '{\"a\":{\"password\":\"hunter\"}}' > '$T/data/config.json'; zc config show | grep -q '\\*\\*\\*\\*'"

# ------------------------------------------- service-user access, hardening ----
section "access is checked as the service user"
reset_scratch
write_config "$T/cfg.json" 8443 no yes
touch "$T/tls/server.crt" "$T/tls/server.key"
echo "$T/tls/server.key" >"$T/deny"
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "unreadable TLS key blocks a fresh install" || bad "unreadable TLS key blocks a fresh install"
check "names the unreadable file" grep -q "cannot read $T/tls/server.key" "$T/out.txt"
check "no unit written when the check fails" test ! -e "$T/units/zot.service"
rm -f "$T/deny"
reset_scratch
touch "$T/tls/server.crt" "$T/tls/server.key"
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >/dev/null 2>&1
check "install works once readable" test "$(cur)" = v1.0.0-a
echo "$T/tls/server.key" >"$T/deny"
zc upgrade --yes --dir "$T/src_b" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "upgrade blocked when the service user lost access" || bad "upgrade blocked when the service user lost access"
check "upgrade changed nothing" test "$(cur)" = v1.0.0-a
check "staged release removed" test ! -d "$T/prefix/releases/v2.0.0-b"
[ "$(rc_of zc verify)" != 0 ] && ok "verify reports the access problem" || bad "verify reports the access problem"
rm -f "$T/deny"

section "health probe selection"
reset_scratch
write_config "$T/cfg.json" 8443 no
make_src "$T/src_hc" v6.0.0-hc
ZC_HEALTH_CMD='' zc install --yes --dir "$T/src_hc" --config "$T/cfg.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "install succeeds using 'zot healthcheck'" || { bad "install using 'zot healthcheck' (rc=$rc)"; cat "$T/out.txt"; }
check "healthcheck was invoked with the installed config, skipping TLS verification" grep -q "healthcheck --insecure-skip-verify $T/data/config.json" "$T/state/healthcheck.calls"
reset_scratch
HC=0 make_src "$T/src_nohc" v0.8.0-nohc
rm -f "$T/state/healthcheck.calls"
WAIT_SECS=2 ZC_HEALTH_CMD='' zc install --yes --dir "$T/src_nohc" --config "$T/cfg.json" >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && ok "build without healthcheck falls back to the /v2/ probe (nothing listens in tests)" || bad "fallback probe"
check "healthcheck subcommand not used for that build" test ! -e "$T/state/healthcheck.calls"

section "hardening and logrotate options"
reset_scratch
write_config "$T/cfg.json" 8443 no
zc install --yes --no-harden --no-logrotate --dir "$T/src_a" --config "$T/cfg.json" >/dev/null 2>&1
check "--no-harden: no sandbox drop-in" test ! -e "$T/units/zot.service.d/zotctl-hardening.conf"
check "--no-logrotate: no logrotate file" test ! -e "$T/logrotate.d/zot"
reset_scratch
write_config "$T/data/config.json" 443 no; existing_host_dirs
NOTIFY=0 make_bin "$T/bin/zot" legacy-0; NOTIFY=0 make_bin "$T/bin/zli" legacy-0
printf '[Service]\nExecStart=%s serve %s\n' "$T/bin/zot" "$T/data/config.json" >"$T/units/zot.service"
touch "$T/state/zot.service.active"
zc upgrade --yes --dir "$T/src_b" >/dev/null 2>&1
check "upgrade of an existing host does not sandbox it by default" test ! -e "$T/units/zot.service.d/zotctl-hardening.conf"
zc upgrade --yes --harden --dir "$T/src_c" >/dev/null 2>&1
check "--harden opts an existing host in" grep -q '^ReadWritePaths=' "$T/units/zot.service.d/zotctl-hardening.conf"
check "--harden created the missing storage directory" test -d "$T/data/images"
make_src "$T/src_e" v5.5.0-e
zc upgrade --yes --dir "$T/src_e" >/dev/null 2>&1
check "hardening stays on at the next upgrade" test -e "$T/units/zot.service.d/zotctl-hardening.conf"
check "verify passes" zc verify
jq --arg p "$T/elsewhere" '.storage.subPaths={"/x":{"rootDirectory":$p}}' "$T/data/config.json" >"$T/c.tmp" && mv "$T/c.tmp" "$T/data/config.json"
zc verify >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "verify flags a config path missing from ReadWritePaths" || bad "verify flags a config path missing from ReadWritePaths"
check "...and says how to fix it" grep -q "zotctl upgrade --harden" "$T/out.txt"
zc upgrade --yes --no-harden --dir "$T/src_d" >/dev/null 2>&1
check "--no-harden removes the sandbox drop-in" test ! -e "$T/units/zot.service.d/zotctl-hardening.conf"

section "an existing htpasswd file keeps its owner and mode"
reset_scratch
write_config "$T/cfg.json" 8443 yes
printf 'old:$2y$05$existinghash\n' >"$T/data/.htpasswd"; chmod 600 "$T/data/.htpasswd"
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && ok "install with an existing htpasswd needs no new user" || bad "install with an existing htpasswd (rc=$rc)"
printf 'another-long-pass\n' >"$T/pw4"; chmod 600 "$T/pw4"
zc user add added --password-file "$T/pw4" >/dev/null 2>&1
check "mode stays 0600" test "$(stat -c %a "$T/data/.htpasswd")" = 600
check "existing entry preserved" grep -q '^old:' "$T/data/.htpasswd"
check "new entry added" grep -q '^added:' "$T/data/.htpasswd"

section "config path validation"
reset_scratch
mkdir -p "$T/cwd"
write_config "$T/cfg.json" 8443 no
jq '.storage.rootDirectory="relative-store"' "$T/cfg.json" >"$T/bad.json"
(cd "$T/cwd" && zc install --yes --dir "$T/src_a" --config "$T/bad.json") >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "relative storage.rootDirectory refused" || bad "relative storage.rootDirectory refused"
check "message names the key and says relative" grep -q "storage.rootDirectory is a relative path (relative-store)" "$T/out.txt"
check "nothing created in the working directory" test -z "$(ls -A "$T/cwd")"
check "nothing installed" test ! -e "$T/prefix/current"
jq 'del(.storage.rootDirectory)' "$T/cfg.json" >"$T/bad.json"
zc install --yes --dir "$T/src_a" --config "$T/bad.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "missing storage.rootDirectory refused" || bad "missing storage.rootDirectory refused"
check "says it is not set" grep -q "storage.rootDirectory is not set" "$T/out.txt"
jq '.log.output="zot.log"' "$T/cfg.json" >"$T/bad.json"
zc install --yes --dir "$T/src_a" --config "$T/bad.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "relative log.output refused" || bad "relative log.output refused"
check "names log.output" grep -q "log.output is a relative path" "$T/out.txt"
jq '.http.tls={"cert":"server.crt","key":"/abs/server.key"} | .storage.subPaths={"/x":{"rootDirectory":"sub"}}' "$T/cfg.json" >"$T/bad.json"
zc install --yes --dir "$T/src_a" --config "$T/bad.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "relative TLS and subPaths paths refused" || bad "relative TLS and subPaths paths refused"
check "reports every problem, not just the first" bash -c "grep -q 'http.tls.cert' '$T/out.txt' && grep -q 'subPaths' '$T/out.txt'"
[ "$(rc_of zc install --dry-run --yes --dir "$T/src_a" --config "$T/bad.json")" != 0 ] && ok "--dry-run refuses too" || bad "--dry-run refuses too"
check "a valid config still installs" bash -c "$(declare -f zc rc_of); T='$T'; ZOTCTL='$ZOTCTL'; DEFAULT_HC='$DEFAULT_HC'; [ \$(rc_of zc install --yes --dir '$T/src_a' --config '$T/cfg.json') = 0 ]"

section "config path problems on an existing host"
reset_scratch
write_config "$T/data/config.json" 8443 no; existing_host_dirs
jq '.log.output="relative.log"' "$T/data/config.json" >"$T/c.tmp" && mv "$T/c.tmp" "$T/data/config.json"
NOTIFY=0 make_bin "$T/bin/zot" legacy-0; NOTIFY=0 make_bin "$T/bin/zli" legacy-0
printf '[Service]\nExecStart=%s serve %s\n' "$T/bin/zot" "$T/data/config.json" >"$T/units/zot.service"
touch "$T/state/zot.service.active"
zc upgrade --yes --harden --dir "$T/src_b" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "upgrade still proceeds (the host already runs with this config)" || { bad "upgrade proceeds (rc=$rc)"; cat "$T/out.txt"; }
check "upgrade warns about the relative path" grep -q "log.output is a relative path" "$T/out.txt"
check "--harden skipped because paths are unreliable" bash -c "grep -q 'skipping hardening' '$T/out.txt' && [ ! -e '$T/units/zot.service.d/zotctl-hardening.conf' ]"
[ "$(rc_of zc verify)" != 0 ] && ok "verify fails on the relative path" || bad "verify fails on the relative path"

# ---------------------------------------------------------- review findings ----
section "preflight validation has no side effects"
reset_scratch
write_config "$T/cfg.json" 8443 no
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "fresh install works although the log directory does not exist yet" || { bad "fresh install with a new log directory (rc=$rc)"; cat "$T/out.txt"; }
check "the first validation ran on a copy without the log files" bash -c "head -1 '$T/state/verify.calls' | grep -qv '\"output\"'"
check "the real config is validated later, as the service user" grep -q '"output"' "$T/state/verify.calls"

section "generated health timer script"
hs="$T/prefix/zot-health.sh"
check "native probe skips TLS verification" grep -q 'healthcheck --insecure-skip-verify' "$hs"
check "wget fallback for hosts without curl" grep -q wget "$hs"
run_hs() { FAKE_STATE="$T/state" ZOT_HEALTH_STATE_FILE="$T/hs.state" PATH="$T/fakebin:$PATH" bash "$hs" >/dev/null 2>&1; }
touch "$T/state/hc.fail" "$T/state/started.old"
rm -f "$T/hs.state"; : >"$T/state/calls"
run_hs; run_hs; run_hs
check "three failed probes of a long-running service restart it" grep -q '^restart zot.service' "$T/state/calls"
rm -f "$T/hs.state"; : >"$T/state/calls"; touch "$T/state/zot.service.activating"
for _ in 1 2 3 4 5; do run_hs; done
check "nothing is restarted while the service is still activating" bash -c "! grep -q '^restart' '$T/state/calls'"
rm -f "$T/state/zot.service.activating" "$T/state/hc.fail" "$T/state/started.old"

section "health timer survives a failed upgrade"
reset_scratch
write_config "$T/cfg.json" 8443 no
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >/dev/null 2>&1
make_src "$T/src_bad2" v9.9.9-bad bad
WAIT_SECS=3 zc upgrade --yes --dir "$T/src_bad2" >/dev/null 2>&1
check "still on the old release" test "$(cur)" = v1.0.0-a
check "health timer is running again (the recovery attempt did not forget the pause)" test -e "$T/state/zot-health.timer.active"

section "health URL follows http.address"
for addr in 10.1.2.3 0.0.0.0 '::'; do
    reset_scratch
    write_config "$T/cfg.json" 8443 no
    jq --arg a "$addr" '.http.address=$a' "$T/cfg.json" >"$T/c2.json"
    zc install --yes --dir "$T/src_a" --config "$T/c2.json" >/dev/null 2>&1
    case $addr in
        10.1.2.3) want='URL=http://10.1.2.3:8443/v2/' ;;
        0.0.0.0) want='URL=http://127.0.0.1:8443/v2/' ;;
        '::') want='URL=http://\[::1\]:8443/v2/' ;;
    esac
    grep -qF "$want" "$T/prefix/zot-health.sh" && ok "address $addr -> $want" || bad "address $addr -> $want"
done

section "log files in a shared directory"
reset_scratch
mkdir -p "$T/shared"; chmod 755 "$T/shared"; echo keep >"$T/shared/other.log"
write_config "$T/cfg.json" 8443 no
jq --arg l "$T/shared/zot.log" '.log.output=$l' "$T/cfg.json" >"$T/c2.json"
zc install --yes --dir "$T/src_a" --config "$T/c2.json" >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && ok "install into a shared log directory succeeds" || bad "install into a shared log directory (rc=$rc)"
check "the existing shared directory keeps its mode" test "$(stat -c %a "$T/shared")" = 755
check "only the log file is created (0640)" test "$(stat -c %a "$T/shared/zot.log")" = 640
rw=" $(sed -n 's/^ReadWritePaths=//p' "$T/units/zot.service.d/zotctl-hardening.conf") "
case $rw in
    *" $T/shared "*) bad "the sandbox exposes the whole shared directory" ;;
    *" $T/shared/zot.log "*) ok "the sandbox lists the log file, not its directory" ;;
    *) bad "the sandbox lists the log file" ;;
esac
echo rotated >"$T/shared/zot.log.1"
zc uninstall --yes --purge-data >/dev/null 2>&1
check "purge removes the log file and its rotated copies" bash -c "[ ! -e '$T/shared/zot.log' ] && [ ! -e '$T/shared/zot.log.1' ]"
check "purge leaves other files in the shared directory alone" test "$(cat "$T/shared/other.log")" = keep

section "deletion paths are canonicalised"
reset_scratch
write_config "$T/cfg.json" 8443 no
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >/dev/null 2>&1
for bad_path in /var/../etc //var /var/./log /usr/../usr /tmp/../etc; do
    FAKE_STATE="$T/state" ZOTCTL_TEST=1 ZOTCTL_UNIT_DIR="$T/units" ZOTCTL_SYSTEMCTL="$T/fakebin/systemctl" ZOTCTL_LOGROTATE_DIR="$T/logrotate.d" \
        "$ZOTCTL" uninstall --dry-run --purge-data --config-dir "$bad_path" --prefix "$T/prefix" --bin-dir "$T/bin" >"$T/out.txt" 2>&1; rc=$?
    [ "$rc" != 0 ] && grep -q "refusing to delete" "$T/out.txt" && ok "purge of $bad_path is refused" || bad "purge of $bad_path is refused"
done

section "htpasswd without a path"
reset_scratch
write_config "$T/cfg.json" 8443 no
jq '.http.auth={"htpasswd":{}}' "$T/cfg.json" >"$T/c2.json"
zc install --yes --dir "$T/src_a" --config "$T/c2.json" --admin-user admin --password-file "$T/pw" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "htpasswd object without a path is refused" || bad "htpasswd object without a path is refused"
check "explains that zot would leave auth disabled" grep -q "http.auth.htpasswd has no path" "$T/out.txt"
check "nothing installed" test ! -e "$T/prefix/current"

section "migration is all-or-nothing"
reset_scratch
write_config "$T/data/config.json" 8443 no; existing_host_dirs
NOTIFY=0 make_bin "$T/bin/zot" legacy-0
ln -s /nonexistent/zli "$T/bin/zli"
printf '[Service]\nExecStart=%s serve %s\n' "$T/bin/zot" "$T/data/config.json" >"$T/units/zot.service"
touch "$T/state/zot.service.active"
zc upgrade --yes --dir "$T/src_b" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && ok "a foreign zli symlink stops the migration" || bad "a foreign zli symlink stops the migration"
check "the existing zot binary was not moved" bash -c "[ -f '$T/bin/zot' ] && [ ! -L '$T/bin/zot' ]"
check "no half-migrated release was left as current" test ! -e "$T/prefix/current"

section "a host without zli gets the managed link"
reset_scratch
write_config "$T/data/config.json" 8443 no; existing_host_dirs
NOTIFY=0 make_bin "$T/bin/zot" legacy-0
printf '[Service]\nExecStart=%s serve %s\n' "$T/bin/zot" "$T/data/config.json" >"$T/units/zot.service"
touch "$T/state/zot.service.active"
zc upgrade --yes --dir "$T/src_b" >/dev/null 2>&1
check "zli link created for the new release" test "$(readlink "$T/bin/zli")" = "$T/prefix/current/zli"
check "zot link created" test "$(readlink "$T/bin/zot")" = "$T/prefix/current/zot"
zc rollback --yes >/dev/null 2>&1
check "rolling back to the release that has no zli drops the link" test ! -e "$T/bin/zli"
check "verify passes on that release" zc verify

section "an existing unit without User= is treated as root"
reset_scratch
write_config "$T/data/config.json" 8443 no; existing_host_dirs
NOTIFY=0 make_bin "$T/bin/zot" legacy-0
printf '[Service]\nExecStart=%s serve %s\n' "$T/bin/zot" "$T/data/config.json" >"$T/units/zot.service"
zc verify >/dev/null 2>&1 || true
check "checks ran as root, not the fresh-install account" bash -c "grep -qx root '$T/state/asuser.log' && ! grep -qx zot '$T/state/asuser.log'"
printf '[Service]\nUser=zot\nExecStart=%s serve %s\n' "$T/bin/zot" "$T/data/config.json" >"$T/units/zot.service"
rm -f "$T/state/asuser.log"
zc verify >/dev/null 2>&1 || true
check "an explicit User= is honoured" grep -qx zot "$T/state/asuser.log"

section "re-running upgrade for the current release still applies unit settings"
reset_scratch
write_config "$T/cfg.json" 8443 no
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" >/dev/null 2>&1
hf="$T/units/zot.service.d/zotctl-hardening.conf"
: >"$T/state/calls"
zc upgrade --yes --no-harden --dir "$T/src_a" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "upgrade of the identical current release succeeds" || { bad "identical release upgrade (rc=$rc)"; cat "$T/out.txt"; }
check "--no-harden removed the sandbox" test ! -e "$hf"
check "zot was restarted to apply it" grep -q '^restart zot.service' "$T/state/calls"
check "the current release is unchanged" test "$(cur)" = v1.0.0-a
: >"$T/state/calls"
zc upgrade --yes --harden --dir "$T/src_a" >/dev/null 2>&1
check "--harden turned it back on" test -e "$hf"
check "and restarted zot" grep -q '^restart zot.service' "$T/state/calls"
: >"$T/state/calls"
zc upgrade --yes --harden --dir "$T/src_a" >"$T/out.txt" 2>&1
check "nothing changed -> nothing to do" grep -q "nothing to do" "$T/out.txt"
check "and no restart" bash -c "! grep -q '^restart' '$T/state/calls'"
check "no self-referential rollback target was recorded" test ! -e "$T/prefix/releases/v1.0.0-a/.previous"
make_src "$T/src_a2" v1.0.0-a; echo '#rebuilt' >>"$T/src_a2/zot"
zc upgrade --yes --dir "$T/src_a2" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" != 0 ] && grep -q "different binaries" "$T/out.txt" && ok "same version string with different binaries is refused" || bad "same version string with different binaries is refused"

section "paths with whitespace, and a config already in place"
reset_scratch
write_config "$T/cfg.json" 8443 no
jq --arg d "$T/data dir/images" '.storage.rootDirectory=$d' "$T/cfg.json" >"$T/c2.json"
zc install --yes --dir "$T/src_a" --config "$T/c2.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "install with a space in the storage path succeeds" || bad "install with a space in the storage path (rc=$rc)"
check "sandbox skipped, with an explanation" bash -c "grep -q 'skipping hardening' '$T/out.txt' && [ ! -e '$T/units/zot.service.d/zotctl-hardening.conf' ]"
check "the directory was created" test -d "$T/data dir/images"
reset_scratch
cp "$T/cfg.json" "$T/data/config.json"
zc install --yes --dir "$T/src_a" --config "$T/data/config.json" >"$T/out.txt" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "--config pointing at the destination file works" || { bad "--config already in place (rc=$rc)"; cat "$T/out.txt"; }
check "and its mode is tightened to 0640" test "$(stat -c %a "$T/data/config.json")" = 640

section "user names are matched exactly"
reset_scratch
write_config "$T/cfg.json" 8443 yes
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --password-file "$T/pw" >/dev/null 2>&1
printf 'long-enough-pass\n' >"$T/pw5"; chmod 600 "$T/pw5"
zc user add johnXdoe --password-file "$T/pw5" >/dev/null 2>&1
[ "$(rc_of zc user add john.doe --password-file "$T/pw5")" = 0 ] && ok "john.doe is not mistaken for johnXdoe" || bad "john.doe is not mistaken for johnXdoe"
[ "$(rc_of zc user passwd john.doe --password-file "$T/pw5")" = 0 ] && ok "passwd works on the exact name" || bad "passwd works on the exact name"
[ "$(rc_of zc user passwd jo.n --password-file "$T/pw5")" != 0 ] && ok "a regex-like name does not match an existing user" || bad "a regex-like name does not match an existing user"
zc user remove john.doe --yes >/dev/null 2>&1
check "removing john.doe leaves johnXdoe" bash -c "grep -q '^johnXdoe:' '$T/data/.htpasswd' && ! grep -q '^john\\.doe:' '$T/data/.htpasswd'"

section "purge removes every storage location"
reset_scratch
write_config "$T/cfg.json" 8443 no
jq --arg a "$T/sub1" --arg c "$T/cache" '.storage.subPaths={"/x":{"rootDirectory":$a}} | .storage.cacheDriver={"name":"boltdb","rootDir":$c}' "$T/cfg.json" >"$T/c2.json"
zc install --yes --dir "$T/src_a" --config "$T/c2.json" >/dev/null 2>&1
check "install created the subPaths and cache directories" bash -c "[ -d '$T/sub1' ] && [ -d '$T/cache' ]"
touch "$T/sub1/blob" "$T/cache/cache.db"
zc uninstall --yes --purge-data >"$T/out.txt" 2>&1
check "purge removed the subPaths directory" test ! -e "$T/sub1"
check "purge removed the cache directory" test ! -e "$T/cache"
check "and the config directory with the root storage" test ! -e "$T/data"
check "the confirmation text listed them" grep -q "storage $T/sub1" "$T/out.txt"

# Optional: exercise the real zot and zli binaries (set ZOTCTL_REAL_BIN_DIR to a directory that
# contains executables named zot and zli). The fake binaries above cannot catch behaviour that
# only the real zot has, such as `zot verify` opening log files and panicking on a missing directory.
if [ -n "${ZOTCTL_REAL_BIN_DIR:-}" ]; then
    section "real zot binary"
    reset_scratch
    write_config "$T/cfg.json" 8443 no
    ZC_HEALTH_CMD='true' zc install --yes --dir "$ZOTCTL_REAL_BIN_DIR" --config "$T/cfg.json" >"$T/out.txt" 2>&1; rc=$?
    [ "$rc" = 0 ] && ok "fresh install with the real zot (log directory did not exist)" || { bad "fresh install with the real zot (rc=$rc)"; cat "$T/out.txt"; }
    check "real zot created the log file as itself, nothing else" test -f "$T/logs/system.log"
    check "real binary type detected: a Type= drop-in was written" test -s "$T/units/zot.service.d/zotctl-type.conf"
    check "zotctl verify passes with the real zot" zc verify
    check "config check passes with the real zot" zc config check
    jq '.log.level="bogus"' "$T/cfg.json" >"$T/bad.json"
    [ "$(rc_of zc install --yes --dir "$ZOTCTL_REAL_BIN_DIR" --config "$T/bad.json")" != 0 ] && ok "the real zot's validation rejects a bad config" || bad "the real zot's validation rejects a bad config"
fi

# ------------------------------------------------------------- uninstall ----
section "uninstall"
reset_scratch
write_config "$T/cfg.json" 8443 yes
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --password-file "$T/pw" >/dev/null 2>&1
# zc appends its own --config-dir, so call zotctl directly to point the purge at /var (dry-run only)
FAKE_STATE="$T/state" ZOTCTL_TEST=1 ZOTCTL_UNIT_DIR="$T/units" ZOTCTL_SYSTEMCTL="$T/fakebin/systemctl" \
    "$ZOTCTL" uninstall --dry-run --purge-data --config-dir /var --prefix "$T/prefix" --bin-dir "$T/bin" >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && ok "refuses to purge a protected directory (dry-run)" || bad "refuses to purge a protected directory (dry-run)"
zc uninstall --yes >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && ok "uninstall succeeds" || bad "uninstall succeeds (rc=$rc)"
check "units removed" test ! -e "$T/units/zot.service" -a ! -e "$T/units/zot-health.timer"
check "logrotate file removed" test ! -e "$T/logrotate.d/zot"
check "hardening drop-in removed" test ! -e "$T/units/zot.service.d/zotctl-hardening.conf"
check "prefix removed" test ! -e "$T/prefix"
check "links removed" test ! -e "$T/bin/zot" -a ! -L "$T/bin/zot"
check "data kept" test -f "$T/data/config.json"
check "second uninstall is a no-op" zc uninstall --yes
zc install --yes --dir "$T/src_a" --config "$T/cfg.json" --admin-user admin --password-file "$T/pw" >/dev/null 2>&1
check "reinstall after uninstall works" test -L "$T/prefix/current"
zc uninstall --yes --purge-data >/dev/null 2>&1
check "--purge-data removes the data dir" test ! -e "$T/data"
[ "$(rc_of zc uninstall --purge-data </dev/null)" = 0 ] && ok "nothing left -> exit 0" || bad "nothing left -> exit 0"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
