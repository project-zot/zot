This allows Zot to indirectly listen at a privileged socket port (e.g. `443`) without granting it the `CAP_NET_BIND_SERVICE` capability.

This uses the [systemd Socket Activation](https://0pointer.de/blog/projects/socket-activated-containers.html) feature to create the listening socket at the privileged port. The port is defined by the `ListenStream` variable declared in the [`zot.socket` file](zot.socket). 

At the first socket client connection, systemd will start the `zot` service, and will pass it the listening socket in the file descriptor defined by the `LISTEN_FDS` environment variable.

To install the `zot` service as described, review the example [`zot.service`](zot.service) and [`zot.socket`](zot.socket) files, and then execute the following commands as the `root` user:

```bash
install zot.service /etc/systemd/system/zot.service
install zot.socket /etc/systemd/system/zot.socket
systemctl daemon-reload
systemctl enable zot.service zot.socket
systemctl restart zot.service zot.socket
```

At development time, you can test the systemd Socket Activation using something like:

```bash
systemd-socket-activate \
    --listen=127.0.0.1:9999 \
    ./bin/zot-linux-amd64 \
    serve \
    examples/config-minimal.json
```
