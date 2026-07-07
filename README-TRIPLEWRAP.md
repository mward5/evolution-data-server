# Evolution-Data-Server — S/MIME Triple-Wrap fork

This is a personal, experimental fork of
[GNOME Evolution-Data-Server](https://gitlab.gnome.org/GNOME/evolution-data-server)
that adds a fallback parser for RFC 2634 S/MIME triple-wrapped
`multipart/signed` messages, so Evolution can verify and decrypt mail that
was triple-wrapped (sign → encrypt → outer sign) by the companion
[`mward5/evolution`](https://github.com/mward5/evolution) composer change.

**Status:** working, tested against Gmail Web; not yet submitted upstream.
Feedback welcome. The intent is to open a merge request against
[gitlab.gnome.org/GNOME/evolution-data-server](https://gitlab.gnome.org/GNOME/evolution-data-server)
once this has seen some real-world use.

See [`docs/SMIME-Triple-Wrap-Design.md`](docs/SMIME-Triple-Wrap-Design.md)
for the full design rationale, threat model, and RFC references
(RFC 2634, RFC 5035, EID 6562).

## Branches

- **`master`** — unmodified mirror of upstream GNOME `master`. Not touched;
  kept for diffing/rebasing against upstream.
- **`triple-wrap-3.60.2`** *(this branch)* — upstream tag `3.60.2` plus two
  commits adding a fallback boundary scanner to
  `camel-multipart-signed.c`. This is the branch a future GNOME merge
  request would be built from.
- **`debian-packaging`** — `triple-wrap-3.60.2` plus a Debian source package
  (`debian/`, format `3.0 (quilt)`) that applies the same change via
  `debian/patches/0006`–`0007`. Builds with `dpkg-buildpackage` /
  `gbp buildpackage`.
- **`fedora-packaging`** — upstream `3.60.2` plus a Fedora dist-git style
  `evolution-data-server.spec` and `Patch0001`/`Patch0002`. Builds with
  `fedpkg` / `rpmbuild -bs` (fetch the `3.60.2` source tarball per
  `sources`).

## What changed

Two commits on top of upstream `3.60.2`, both in
[`src/camel/camel-multipart-signed.c`](src/camel/camel-multipart-signed.c):

1. **`multipart-signed: fallback when parser fails (triple-wrap / base64 body)`**
   When the normal MIME parser can't find two parts in a `multipart/signed`
   body — which happens for triple-wrapped messages and for bodies stored
   with `Content-Transfer-Encoding: base64` — scan the raw bytes for the
   MIME boundary directly and set the part offsets from that, so
   verification and decryption can proceed instead of failing with a parse
   error.
2. **`multipart-signed: use g_debug for fallback parse failures, fix comment typo`**
   Downgrades the fallback path's failure messages from `g_warning` to
   `g_debug` so normal logs stay quiet, and fixes a comment typo.

## Building

```sh
git clone -b triple-wrap-3.60.2 https://github.com/mward5/evolution-data-server.git
git clone -b triple-wrap-3.60.2 https://github.com/mward5/evolution.git
# build/install this repo first, then evolution against it, per the
# normal Evolution-Data-Server CMake build.
```

For a distro package instead, use the `debian-packaging` or
`fedora-packaging` branch of each repo.

## License

Unchanged from upstream: LGPL-2.1-or-later (see `COPYING`).
