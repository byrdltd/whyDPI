# whydpi-git (AUR)

Upstream-tracking PKGBUILD for [whyDPI](https://github.com/byrdltd/whyDPI).

The canonical copy lives in the AUR at
<https://aur.archlinux.org/packages/whydpi-git> and is built from the
`main` branch of this repository.  This directory is the master copy —
changes made here must be mirrored to the AUR repo.

## Publishing a new revision

```bash
# 1. Edit PKGBUILD here, bump pkgrel if only packaging changed
cd packaging/aur/whydpi-git
makepkg --printsrcinfo > .SRCINFO

# 2. Test-build locally
(cp PKGBUILD .SRCINFO /tmp/build && cd /tmp/build && makepkg -f)

# 3. Push to AUR
cd /tmp/whydpi-aur
git clone ssh://aur@aur.archlinux.org/whydpi-git.git
cp ../whyDPI/packaging/aur/whydpi-git/{PKGBUILD,.SRCINFO} whydpi-git/
cd whydpi-git
git add PKGBUILD .SRCINFO
git commit -m "Update to <pkgver>-<pkgrel>"
git push
```

## Notes

- `pkgver()` auto-derives version from `setup.py` + git commit count,
  so users always pick up the very latest `main` at rebuild time.
- The package ships a `whydpi.service` unit but does **not** enable it —
  that stays an explicit user decision.
