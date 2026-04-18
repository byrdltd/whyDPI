# whydpi — Debian / Ubuntu packaging

This directory produces the `.deb` package for Debian-family distros.
The files are kept under `packaging/debian/` to keep the repository
root clean; `build-deb.sh` copies them to `./debian/` on the fly for
`dpkg-buildpackage`.

## Local build (in a clean Debian container)

```bash
podman run --rm \
  -v "$PWD:/src:ro" \
  -v "$PWD/packaging/debian/dist:/out:rw,Z" \
  docker.io/library/debian:bookworm bash -c '
    apt-get update && apt-get install -y \
      build-essential devscripts dpkg-dev debhelper dh-python \
      python3-all python3-build python3-setuptools python3-wheel \
      pybuild-plugin-pyproject lintian git
    cp -a /src /build/whyDPI && cd /build/whyDPI
    packaging/debian/build-deb.sh
    cp packaging/debian/dist/* /out/
  '
```

Output lands in `packaging/debian/dist/`.

## Tested on

| Distribution     | Python | Status |
| ---              | ---    | ---    |
| Debian 12 (bookworm) | 3.11 | OK   |
| Ubuntu 24.04 (noble) | 3.12 | OK   |
| Ubuntu 22.04 (jammy) | 3.10 | OK   |

## Launchpad PPA upload

When ready to publish to Launchpad:

1. Create a Launchpad account and upload an OpenPGP public key.
2. Per target Ubuntu release, add a changelog entry with the release
   suffix (e.g. `0.2.0-1~noble1`, `0.2.0-1~jammy1`).
3. Build a signed **source** package (not binary):
   ```bash
   cd /tmp/build
   dpkg-buildpackage -S -sa -k<GPG-KEY-ID>
   ```
4. Upload with `dput`:
   ```bash
   dput ppa:byrdltd/whydpi ../whydpi_0.2.0-1~noble1_source.changes
   ```
5. Launchpad's build farm produces the binary `.deb` on real Ubuntu
   infrastructure and publishes it to the PPA archive within ~15 min.
