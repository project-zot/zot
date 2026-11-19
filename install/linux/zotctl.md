# zotctl

`zotctl` installs, upgrades, rolls back and manages a zot registry on any
Linux host that runs systemd. It manages the *host-side* install (binaries,
systemd unit, htpasswd users); use `zli` to talk to a running registry.

```text
sudo zotctl install --config config.json [--dir PATH | --version TAG] \
    [--admin-user NAME]
sudo zotctl upgrade [--dir PATH | --version TAG]
sudo zotctl rollback [--to ID]
sudo zotctl uninstall [--purge-data] [--remove-user] [--keep-binaries]
zotctl status | releases [--available] | verify | config check|path|show
zotctl version
sudo zotctl prune [--keep N] [--older-than DAYS] [--release ID]... \
    [--include-legacy]
sudo zotctl user add|passwd|remove NAME | user list
sudo zotctl start|stop|restart | zotctl logs [--follow]
```

Run `zotctl --help` for all options. Global flags: `--dry-run`, `--yes`,
`--prefix` (default `/opt/zot`), `--bin-dir`, `--config-dir` (the directory
with `config.json` and the htpasswd file; default `/etc/zot` for new
installs). Exit codes: 0 ok, 1 failure, 2 usage error, 3 missing dependencies.

## Getting zotctl

`zotctl` is published as a release asset next to the zot binaries, and it is
covered by the release's `checksums.sha256.txt`. Use a release tag that
includes it:

```shell
TAG=<release tag>
BASE=https://github.com/project-zot/zot/releases/download/$TAG
curl -fLO $BASE/zotctl
curl -fLO $BASE/checksums.sha256.txt
grep ' \*zotctl$' checksums.sha256.txt | sha256sum -c -
sudo install -m 0755 zotctl /usr/local/bin/zotctl
```

`zotctl install` also copies itself into the bin directory if it is not
already there.

## Sources

- **GitHub release** (default): `--version TAG` (default `latest`),
  `--variant extended|minimal|debug` (default `extended`),
  `--repo OWNER/REPO` (default `project-zot/zot`). The `zot-linux-<arch>` and
  `zli-linux-<arch>` assets are downloaded and checked against the release's
  `checksums.sha256.txt` before anything is installed. The architecture comes
  from `uname -m` (amd64 and arm64 are supported).
- **Local folder**: `--dir PATH` containing executables named `zot` and `zli`.

`--dir` and `--version` are mutually exclusive.

## Layout

```text
<prefix>/releases/<id>/{zot,zli,SHA256SUMS,.previous}
<prefix>/current  -> releases/<id>
<bin-dir>/zot, <bin-dir>/zli -> <prefix>/current/...
```

`.previous` holds the id of the release that a release replaced. `rollback`
follows it, so repeated rollbacks walk back through history;
`rollback --to ID` jumps to any retained release. `prune` never removes the
current release or the one `rollback` would return to.

A release id is the release tag, with the variant appended for non-default
builds (`v2.1.22-minimal`), or the version string of the binary for `--dir`.
Upgrading to a release that is already installed with identical binaries is
a no-op except that any requested unit settings (`--harden`, `--no-harden`)
are still applied; the same id with different binaries is refused.

`upgrade` on a host where zot was installed by hand moves the existing
binaries into `releases/legacy-<timestamp>` and replaces them with links, so
it can always be undone.

## Ownership and permissions

On a fresh install the config directory is `root:root` (0755), `config.json`
is `root:zot` 0640 and the htpasswd file is `root:zot` 0640, so the zot
process can read them but a compromised zot cannot rewrite its own config or
user list. Storage directories from the config that do not exist yet are
created for the `zot` account (0750), and so are the log files. Anything that
already exists is left exactly as it is, in particular the directory of a log
file, which may be shared (`/var/log`); only the log file itself is created and
owned by `zot`. `upgrade` never changes ownership or modes on an existing
install.

zotctl takes every directory from the config rather than assuming one: the
storage root, `subPaths`, cache and log directories, TLS files and the
htpasswd path. They must be absolute paths, because zot resolves a relative
one against its own working directory. `install` refuses a config where
`storage.rootDirectory` is unset or any of these paths is relative, and lists
every problem. `upgrade` warns and skips sandboxing, and `verify` fails.

`zot verify` opens the log files named in the config (creating them, and
panicking if their directory is missing), so the early validation, before any
change, runs on a copy of the config without the log files. The real config is
validated afterwards, once the directories exist.

Before activating a release, zotctl then runs `zot verify` **as the service
account** and checks that the account can read the config, TLS certificate
and key and htpasswd file, can write the storage directories and existing log
files, and that the directory of every log file exists (zot cannot create
it). A key that only root can read, as with a default Let's Encrypt `live/`
directory, is reported up front instead of as a failed start. `zotctl verify`
repeats these checks.

## Port 443

The service gets `AmbientCapabilities=CAP_NET_BIND_SERVICE` (and a matching
bounding set) from systemd when the configured port is below 1024. No
`setcap` on the binary is needed, so replacing binaries can never break
binding. On migrated hosts this is written as a drop-in,
`zot.service.d/zotctl.conf`.

## Start type (Type=notify vs simple)

zot builds that send the systemd ready notification (`READY=1`) run as
`Type=notify`, so `systemctl start` returns only once zot is serving, not
while its startup dedupe/GC scan is still running. Older builds never send
it, and systemd would kill them after the start timeout, so they run as
`Type=simple`. zotctl probes each release's binary for the notification and
writes `zot.service.d/zotctl-type.conf` accordingly on every install, upgrade
and rollback. `--start-timeout T` (default `5min`) sets `TimeoutStartSec` for
notify builds; raise it for very large stores.

## Hardening

Fresh installs get a sandboxing drop-in, `zot.service.d/zotctl-hardening.conf`
(`--no-harden` skips it): `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome=read-only`, `PrivateTmp`, kernel and cgroup protection, and
`ReadWritePaths=` derived from the config (`storage.rootDirectory`, every
`storage.subPaths` directory, `storage.cacheDriver.rootDir`, and the log
directories). The ambient capability keeps working under `NoNewPrivileges`.
On an existing host, `zotctl upgrade --harden` opts in and `--no-harden`
removes it; once present, each upgrade refreshes it from the config.
`zotctl verify` flags a writable path in the config that the drop-in does not
cover.

## Health checks and logs

zotctl waits for readiness with `zot healthcheck <config>` (the `readyz`
endpoint, using the listener, address and TLS settings from the config) when
the binary has it, and falls back to `GET /v2/` for older builds. The probe is
local, so it passes `--insecure-skip-verify`: certificates are normally issued
for the public name, not `127.0.0.1`. The fallback probes the `http.address`
from the config (wildcard addresses map to loopback). The generated health timer
script makes the same choice each run, so it follows a rollback to an older
binary. It does nothing while the service is still activating, so a long
startup scan is never interrupted, and it falls back to `wget` when `curl` is
missing.

Fresh installs also write `/etc/logrotate.d/zot` (weekly, 8 rotations,
compressed). zot treats `SIGHUP` as a shutdown request, so rotation uses
`copytruncate` and never signals the process. `--no-logrotate` skips it.

## Binding port 443 with socket activation

As an alternative to the ambient capability, zot can inherit a socket from
systemd (see the install guide). zotctl does not set that up; a `zot.socket`
unit that you add yourself works alongside it.

## Users and passwords

Passwords are never accepted as command-line values. They are prompted for
(twice, no echo), or read from `--password-file FILE` (must be mode 0600),
`--password-stdin`, or `ZOTCTL_PASSWORD`. Hashes are written with
`htpasswd -B` (bcrypt, the only format zot accepts) to the path in the
config's `http.auth.htpasswd.path`, atomically. A new file is `root:zot` 0640;
an existing file keeps its owner and mode. zot watches the file, so no restart
is needed. `install` creates the first user
(`--admin-user`, or a prompt) when the config enables htpasswd auth and the
file does not already exist.

## Safety

- Everything is verified before the service is touched (checksums, `--version`
  of both binaries, `zot verify` of the live config with the new binary).
- Upgrades pause the health timer, and automatically switch back to the
  previous release if zot is not answering within `WAIT_SECS` (default 600).
- `uninstall` keeps data, logs and the service account unless told otherwise;
  `--purge-data` shows everything it will delete (the config directory, every
  storage location from the config including `subPaths` and the cache, and the
  log files with their rotated copies, but never the log directory), requires
  typing `delete` (or `--yes`), and refuses top-level or system directories
  after resolving `..`, repeated slashes and symlinked parents.
- `--dry-run` prints every state-changing step and changes nothing (downloads
  still go to a temp directory so checksums can be verified).

## Dependencies

zotctl checks for what it needs up front and, if anything is missing, lists it
with the reason and the install command for your distribution, then exits 3.
Needed: systemd, coreutils, `sha256sum` (or `shasum`), `curl` (or `wget`),
`jq` (to read the config), `useradd` (or `adduser`) for a fresh install, and
`htpasswd` (apache2-utils / httpd-tools) only when creating htpasswd users.

## Tests

`install/linux/zotctl_test.sh` runs unprivileged against a scratch directory
with fake `systemctl`, `htpasswd` and zot binaries. The fake zot mimics the real
one where it matters (a missing log directory is fatal). It does not exercise
real systemd or bcrypt. Set `ZOTCTL_REAL_BIN_DIR` to a directory containing real
`zot` and `zli` executables to also run a scenario against them.
