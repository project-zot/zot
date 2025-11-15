# NixOS Build for zot

This directory contains Nix build configurations for building zot and its related tools.

## Prerequisites

- [Nix](https://nixos.org/download.html) package manager installed
- Optionally enable [flakes](https://nixos.wiki/wiki/Flakes) for better experience

## Building with Nix Flakes (Recommended)

**Note:** If you haven't enabled flakes globally, you'll need to add `--extra-experimental-features 'nix-command flakes'` to the nix commands, or the Makefile will handle this automatically.

### Build zot (full version with all extensions)
```bash
cd build/nixos
nix --extra-experimental-features 'nix-command flakes' build .#zot
```

### Build zot-minimal (minimal version without extensions)
```bash
cd build/nixos
nix --extra-experimental-features 'nix-command flakes' build .#zot-minimal
```

### Build zli (CLI tool)
```bash
cd build/nixos
nix --extra-experimental-features 'nix-command flakes' build .#zli
```

### Build zb (benchmark tool)
```bash
cd build/nixos
nix --extra-experimental-features 'nix-command flakes' build .#zb
```

The built binaries will be available in `./result/bin/`

## Building with traditional Nix (without flakes)

```bash
nix-build build/nixos/default.nix
```

## Building from the Makefile

From the project root:
```bash
make binary-nixos          # Build zot with Nix
make binary-nixos-minimal  # Build zot-minimal with Nix
make cli-nixos             # Build zli with Nix
make bench-nixos           # Build zb with Nix
```

## Environment Variables

You can customize the build by setting environment variables:

- `RELEASE_TAG`: Set the release version tag
- `COMMIT`: Set the git commit hash
- `GO_VERSION`: Set the Go version
- `BUILD_LABELS`: Comma-separated list of extension labels

Example:
```bash
RELEASE_TAG=v2.0.0 COMMIT=$(git rev-parse HEAD) nix --extra-experimental-features 'nix-command flakes' build .#zot
```

## Enabling Flakes Permanently (Optional)

To avoid adding the `--extra-experimental-features` flag every time, you can enable flakes permanently:

**For single-user Nix installations:**
```bash
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

**For multi-user/NixOS installations:**
Add to `/etc/nix/nix.conf`:
```
experimental-features = nix-command flakes
```

Then restart the Nix daemon:
```bash
sudo systemctl restart nix-daemon
```

## Troubleshooting

### Permission denied error on daemon socket

If you get an error like:
```
error: getting status of /nix/var/nix/daemon-socket/socket: Permission denied
```

This means you need to be in the `nix-users` group or the Nix daemon needs to be started. Try:

1. **Check if you're in the nix-users group:**
   ```bash
   groups | grep nix-users
   ```

2. **If not, add yourself to the group:**
   ```bash
   sudo usermod -aG nix-users $USER
   ```
   Then log out and log back in for the changes to take effect.

3. **Ensure the Nix daemon is running:**
   ```bash
   sudo systemctl status nix-daemon
   sudo systemctl start nix-daemon
   ```

4. **Alternative: Use single-user mode** (if you have permissions):
   ```bash
   # Uninstall multi-user Nix and reinstall in single-user mode
   # This gives you direct access without daemon requirements
   ```

### Build using traditional Go toolchain as fallback

If Nix setup is problematic, you can always fall back to the standard Go build:
```bash
make binary          # Standard Go build
make binary-minimal
make cli
make bench
```

## Updating Dependencies

When Go dependencies change, you'll need to update the `vendorHash` in `flake.nix`:

1. Set `vendorHash = null;` in the package definition
2. Run the build: `nix --extra-experimental-features 'nix-command flakes' build .#zot`
3. Nix will fail and show the correct hash in the error message
4. Update `vendorHash` with the hash from the error message
5. Rebuild

## Notes

- All binaries are built with CGO disabled for maximum portability
- Binaries are statically linked
- Debug symbols are stripped for smaller binary size
