# whydpi — Fedora packaging

This directory produces the `.rpm` package for Fedora.  The spec file
lives at `packaging/fedora/whydpi.spec`; `build-rpm.sh` is a wrapper
that assembles an `%{_topdir}` tree on the fly and runs `rpmbuild`.

## Local build (in a clean Fedora container)

```bash
podman run --rm \
  -v "$PWD:/src:ro" \
  -v "$PWD/packaging/fedora/dist:/out:rw,Z" \
  docker.io/library/fedora:41 bash -c '
    dnf install -y rpm-build python3-devel python3-setuptools \
                   python3-build python3-installer python3-wheel \
                   systemd-rpm-macros git tar
    cp -a /src /build/whyDPI && cd /build/whyDPI
    packaging/fedora/build-rpm.sh
    cp packaging/fedora/dist/*.rpm /out/
  '
```

## Tested on

| Distribution | Python | Status |
| ---          | ---    | ---    |
| Fedora 41    | 3.13   | OK     |

Fedora 40 needs a separate build because RPM bakes the exact Python
ABI (`python(abi) = 3.12`) into the package; one `.rpm` therefore
cannot span Fedora major versions.  The GitHub Actions workflow in
`.github/workflows/release.yml` builds per-target.

## Fedora COPR upload

When ready to publish via [COPR](https://copr.fedorainfracloud.org):

1. Create a Fedora Account System (FAS) account.
2. Create a COPR project (`byrdltd/whydpi`).
3. Point COPR at this GitHub repo + spec file; COPR's build farm
   produces `.rpm` for every Fedora release automatically.

Until then, the GitHub release attaches a prebuilt `.rpm` users can
install directly with `sudo dnf install <url>`.
