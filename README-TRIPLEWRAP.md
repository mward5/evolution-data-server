# Evolution-Data-Server — S/MIME Triple-Wrap fork

A personal, experimental fork of
[GNOME Evolution-Data-Server](https://gitlab.gnome.org/GNOME/evolution-data-server)
carrying the Camel-side changes for S/MIME triple-wrapping (sign → encrypt →
outer sign), companion to the composer change in
[`mward5/evolution`](https://github.com/mward5/evolution).

**Status:** builds and runs; the camel tests pass and the generated messages
have been verified structurally and cryptographically, but **not** yet confirmed
end-to-end through a mail security gateway. Not submitted upstream.

See [`docs/SMIME-Triple-Wrap-Design.md`](docs/SMIME-Triple-Wrap-Design.md) for
the design, the signature scopes, and the list of RFC 2634 features this does
*not* implement.

## What changed

Six commits on top of upstream `3.60.2`.

In [`src/camel/camel-multipart-signed.c`](src/camel/camel-multipart-signed.c):

1. **`multipart-signed: fallback when parser fails (triple-wrap / base64 body)`**
   When the MIME parser cannot find two parts in a `multipart/signed` body,
   scan the raw bytes for the boundary and set the part offsets from that, so
   verification and decryption can proceed instead of failing outright. The
   case this exists for is a body that arrived base64-encoded, which a
   `multipart` may not be (RFC 2045 §6.4).
2. **`multipart-signed: use g_debug for fallback parse failures, fix comment typo`**
   Keeps normal logs quiet.
3. **`multipart-signed: do not overwrite the body when scanning for boundaries`**
   The fallback base64-decoded the body in place, before knowing whether the
   decoded data contained the boundaries at all. Since
   `multipart_signed_write_to_stream_sync()` writes the stored byte array back
   verbatim, that sent a decoded body under the original
   `Content-Transfer-Encoding` on any re-serialisation. The decoded copy is now
   kept alongside the stored body, which stays untouched.
4. **`multipart-signed: require a line end after the boundary delimiter`**
   `--boundary` was matched without checking what followed, so a longer
   boundary starting the same way matched too. RFC 2046 §5.1.1 allows only
   transport padding and the end of the line there.

In [`src/camel/camel-smime-context.c`](src/camel/camel-smime-context.c):

5. **`smime: Describe the signature part, as the OpenPGP code does`**
   `camel_gpg_context` sets a `Content-Description` on its signature part, and
   `camel_smime_context` sets one on the parts it returns from signing and
   encrypting, but not on the signature part itself. Note this affects **every**
   S/MIME signed message, not only triple-wrapped ones.

And:

6. **`camel: Add a test for the multipart/signed boundary scan`**
   [`src/camel/tests/message/test-multipart-signed.c`](src/camel/tests/message/test-multipart-signed.c),
   covering both the preserved raw body and the boundary-prefix case. Both
   cases fail against the code as it stood before commits 3 and 4.

## Branches

- **`master`** — unmodified mirror of upstream GNOME `master`, for diffing and
  rebasing.
- **`triple-wrap`** *(this branch)* — upstream tag `3.60.2` plus the six
  commits above. A future GNOME merge request would be built from here, after
  squashing. Rebased onto newer upstream tags in place rather than renamed per
  version.
- **`debian-packaging`** — a Debian source package (format `3.0 (quilt)`)
  applying the same changes via `debian/patches/0006`–`0011`. Builds with
  `dpkg-buildpackage` / `gbp buildpackage`.
- **`fedora-packaging`** — a Fedora dist-git style `evolution-data-server.spec`
  with `Patch0001`–`Patch0006`. Builds with `fedpkg` / `rpmbuild -bs` (fetch
  the `3.60.2` tarball per `sources`).

Both packaging branches are regenerated from `triple-wrap` and keep no history
of their own.

## Building

```sh
git clone -b triple-wrap https://github.com/mward5/evolution-data-server.git
git clone -b triple-wrap https://github.com/mward5/evolution.git
```

Build and install this repo first, then evolution against it, per the normal
CMake build. Both halves are required: the Camel changes alone do not produce
triple-wrapped mail.

For distro packages, use the `debian-packaging` or `fedora-packaging` branch of
each repo instead.

## License

Unchanged from upstream: LGPL-2.1-or-later (see `COPYING`).
