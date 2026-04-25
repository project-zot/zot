# Systemd Socket Activation

This example lets zot listen on a privileged port such as `80` or `443` without granting the zot
process `CAP_NET_BIND_SERVICE`.

Systemd creates the listening socket from `ListenStream` in `zot.socket`. When the first client
connects, systemd starts `zot.service` and passes the listener to zot through the socket activation
file descriptor environment.

Install the example units as `root` after reviewing the paths and port:

```bash
install zot.service /etc/systemd/system/zot.service
install zot.socket /etc/systemd/system/zot.socket
systemctl daemon-reload
systemctl enable zot.socket
systemctl start zot.socket
```

For local development, build zot and run it through `systemd-socket-activate`:

```bash
systemd-socket-activate \
  --listen=127.0.0.1:9999 \
  ./bin/zot-linux-amd64 \
  serve \
  examples/config-minimal.json
```
