# whydpi (AUR)

Stable PKGBUILD for [whyDPI](https://github.com/byrdltd/whyDPI), built from
GitHub release tarballs.

The canonical copy lives in the AUR at
<https://aur.archlinux.org/packages/whydpi> and is built from the
`vX.Y.Z` release tag.  This directory is the master copy — changes made
here must be mirrored to the AUR repo.

## Publishing a new stable revision

```bash
# 1. Tag + release on GitHub first (vX.Y.Z)
cd packaging/aur/whydpi

# 2. Bump pkgver in PKGBUILD, refresh checksums
sed -i "s/^pkgver=.*/pkgver=X.Y.Z/" PKGBUILD
sed -i "s/^pkgrel=.*/pkgrel=1/" PKGBUILD
updpkgsums

# 3. Regenerate .SRCINFO
makepkg --printsrcinfo > .SRCINFO

# 4. Test-build locally
(cp PKGBUILD .SRCINFO /tmp/build && cd /tmp/build && makepkg -f)

# 5. Push to AUR
AURDIR=$(mktemp -d)
git -C "$AURDIR" clone ssh://aur@aur.archlinux.org/whydpi.git
cp PKGBUILD .SRCINFO "$AURDIR/whydpi/"
cd "$AURDIR/whydpi"
git add PKGBUILD .SRCINFO
git commit -m "Update to X.Y.Z-1"
git push
```

## When to bump which number

- **`pkgver`**: new upstream release. Always reset `pkgrel=1`.
- **`pkgrel`**: the packaging itself changed but upstream did not (e.g.
  added a missing dependency, changed install path).  Increment by 1.
