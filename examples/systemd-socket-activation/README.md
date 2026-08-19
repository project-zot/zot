# Systemd Socket Activation

This example lets zot listen on a privileged port such as `80` or `443` without granting the zot
process `CAP_NET_BIND_SERVICE`.

Systemd creates the listening socket from `ListenStream` in `zot.socket`. When the first client
connects, systemd starts `zot.service` and passes the listener to zot through the socket activation
file descriptor environment.

## Port Configuration

The `http.port` in the zot config must match the `ListenStream` port in `zot.socket`.
For example, if `zot.socket` has `ListenStream=5000`, set `"port": "5000"` in your zot config.

If `http.port` is set to `"0"`, zot accepts whatever port systemd provides
without validation. This is useful when systemd owns the bind entirely.

> **Note**: Omitting `http.port` entirely is not the same as setting it to `"0"`.
> The default is `"8080"`, which will require the activated port to match.

**Do not** string-compare addresses: systemd may pass `[::]:80` while the config says
`0.0.0.0` or `127.0.0.1`. Only the port number is validated.

## Installation

Install the example units as `root` after reviewing the paths and port:

```bash
install zot.service /etc/systemd/system/zot.service
install zot.socket /etc/systemd/system/zot.socket
systemctl daemon-reload
systemctl enable zot.socket
systemctl start zot.socket
```

## Local Development

Build zot and test socket activation locally with `systemd-socket-activate`.

**Example 1: Explicit port (config port matches)**

Set `"port": "5000"` in `examples/config-minimal.json`, then:

```bash
systemd-socket-activate \
  --listen=127.0.0.1:5000 \
  ./bin/zot-linux-amd64 \
  serve \
  examples/config-minimal.json
```

**Example 2: Unspecified port (systemd owns the bind)**

Set `"port": "0"` in `examples/config-minimal.json`, then:

```bash
systemd-socket-activate \
  --listen=127.0.0.1:3000 \
  ./bin/zot-linux-amd64 \
  serve \
  examples/config-minimal.json
```

Zot will accept any port systemd provides when `http.port` is `"0"`.
