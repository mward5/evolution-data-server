# S/MIME Triple-Wrap in Evolution / Evolution-Data-Server

## 1. Scope

This document describes the S/MIME triple-wrapping (sign → encrypt → sign)
support added to the Evolution composer and to Camel, why it exists, and —
importantly — which parts of RFC 2634 it does **not** implement.

It covers the send path in Evolution and one receive-side parsing fix in Camel.
It is not an S/MIME tutorial.

References:

- RFC 5652 — Cryptographic Message Syntax
- RFC 8551 — S/MIME 4.0 Message Specification
- RFC 2634 — Enhanced Security Services for S/MIME (triple wrapping is §1.1)
- RFC 2045 §6.4 — transfer encodings permitted on `multipart` entities
- RFC 2046 §5.1.1 — boundary delimiter syntax

---

## 2. Problem

Evolution's sign+encrypt produces a two-layer message: an opaque `signed-data`
wrapped in `enveloped-data`, with `application/pkcs7-mime` at the top level.
There is no signature over the encrypted body.

Gmail will not decrypt such a message. The symptom is not a bounce or a
rejection: it is delivered, but the recipient sees an empty body with an
`smime.p7m` attachment. Mail arriving *from* Google Workspace accounts with
hosted S/MIME is triple-wrapped, with an outer `multipart/signed` over the
`enveloped-data` part.

The practical effect is that Evolution cannot send readable encrypted mail to a
Google Workspace recipient, which is a large share of the corporate users who
have S/MIME deployed at all.

The reason is the Efail vulnerability. As a mitigation, Gmail decrypts only
S/MIME messages that are triple wrapped per RFC 2634; anything else is left as
an `smime.p7m` attachment. Thunderbird made a comparable change after Efail,
refusing to decrypt unless the encryption layer is outermost.

That requirement is not in Google's own published documentation as far as we
have found, but it is described consistently by third parties who had to
interoperate with it, including a commercial encrypted-mail service that
implemented triple wrapping specifically for Gmail compatibility:

  https://formsmarts.com/gmail-smime-encrypted-email

There is an apparent contradiction worth addressing, because a reviewer who
knows the Efail paper will raise it: the paper has a section headed "Meaningless
signatures" arguing that signatures do *not* defend against these attacks. Its
grounds are that a signature can simply be stripped, that a user notices too
late, that signatures cannot be made mandatory, and that an invalid signature
does not usually stop a client rendering the message anyway.

Every one of those describes a client that *reports* signature status. They do
not hold against a provider that *enforces* it. If a message is not decrypted
at all without a valid signature over the ciphertext, then stripping the
signature yields a message that is not decrypted, and a tampered ciphertext —
the malleability gadget attacks — fails the signature and is not decrypted
either. Nothing is rendered, so there is no window in which plaintext leaks.

The paper's own preferred fix, authenticated encryption, requires a standards
change that has not happened: CMS defines AuthenticatedData but S/MIME still
does not adopt it. Requiring a signature over the ciphertext is what can be
built from the primitives S/MIME actually has today.

The residual cost is the paper's third objection, and it is real: a recipient
on such a provider cannot receive unsigned encrypted mail at all.

---

## 3. Architecture

**Evolution (composer)** decides whether to sign and/or encrypt, assembles the
MIME tree, and delegates crypto to Camel.

- `src/composer/e-msg-composer.c` — `composer_build_message_smime()`

**Evolution-Data-Server (Camel)** implements the S/MIME operations over NSS.

- `src/camel/camel-cipher-context.[ch]` — abstract sign/encrypt/verify/decrypt
- `src/camel/camel-smime-context.c` — NSS-backed S/MIME implementation
- `src/camel/camel-multipart-signed.c` — `multipart/signed` parsing

---

## 4. What the composer produces

For a message that is both signed and encrypted:

```
multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"
├── application/pkcs7-mime; smime-type="enveloped-data"   (base64)
│     └── [encrypted] application/pkcs7-mime; smime-type="signed-data"
│           └── [signed] the original body part
└── application/pkcs7-signature; name="smime.p7s"          (base64)
```

Three passes, in `composer_build_message_smime()`:

1. **Inner sign** — `CAMEL_SMIME_SIGN_ENVELOPED`, over the composed body part.
   Produces opaque `signed-data`.
2. **Encrypt** — over the result of step 1, including its `Content-*` headers.
   Produces `enveloped-data`.
3. **Outer sign** — `CAMEL_SMIME_SIGN_CLEARSIGN` with SHA-256, over the
   `enveloped-data` **body part**: its `Content-*` headers and its body, and
   nothing else. Produces the outer `multipart/signed`.

### 4.1 Signature scopes

The two signatures cover different data by design, and neither covers the
message's RFC822 headers:

| Signature | Covers |
| --- | --- |
| Inner | `Content-Type`, `Content-Transfer-Encoding`, and the original body |
| Outer | the `Content-*` headers of the `enveloped-data` part, and its base64 body |

Step 3 must be given a body part, not the `CamelMimeMessage`. Camel signs a MIME
entity by serialising it — headers, blank line, body — through
`camel_cipher_canonical_to_stream()`. Since `CamelMimeMessage` derives from
`CamelMimePart`, passing the message compiles and runs, but serialises every
RFC822 header into the signed bytes, including the internal `X-Evolution-*`
headers that are otherwise stripped before sending. The composer therefore
copies the encrypted content and its `Content-*` headers onto a fresh
`CamelMimePart` and signs that.

### 4.2 Headers on the root part

After the encrypt step the message carries `Content-Disposition`,
`Content-Description` and `Content-Transfer-Encoding: base64` describing the
`enveloped-data` part. Once that part is nested inside the outer
`multipart/signed`, they describe the wrong entity and are removed. The encoding
header matters most: a `multipart` body may not be base64-encoded (RFC 2045
§6.4), so leaving it would make the message malformed.

The header is removed rather than reset to `7bit`, because
`camel_mime_part_set_encoding()` writes an *empty* header for the default
encoding, and because messages arriving from Gmail carry no encoding header on
the outer multipart at all.

---

## 5. What is *not* implemented

RFC 2634 is *Enhanced Security Services*. Triple wrapping is one section of it;
most of the document defines CMS attributes. **None of those attributes are
implemented here.**

| RFC 2634 | Status |
| --- | --- |
| §1.1 triple wrapping structure | implemented |
| §2 receipt request | not implemented |
| §3 ESS security label | not implemented |
| §5 signing-certificate attribute | not implemented |
| RFC 5035 `SigningCertificateV2` / `ESSCertIDv2` | not implemented |

The signed attributes Camel actually emits are:

| OID | Attribute |
| --- | --- |
| 1.2.840.113549.1.9.3 | `contentType` (RFC 5652, mandatory) |
| 1.2.840.113549.1.9.4 | `messageDigest` (RFC 5652, mandatory) |
| 1.2.840.113549.1.9.5 | `signingTime` |
| 1.2.840.113549.1.9.16.2.11 | `id-smime-aa-encrypKeyPref` (RFC 8551) |
| 1.3.6.1.4.1.311.16.4 | Microsoft encryption key preference |

NSS does not add ESS attributes of its own accord. This was checked against a
generated message rather than assumed.

The distinction matters for how the work is described: it **produces RFC 2634
triple-wrapped messages**; it does not **implement RFC 2634**. §3 is the notable
gap — in RFC 2634 the outer signature exists largely so a gateway can read and
act on a security label without decrypting, and no such label is carried here.
The outer signature only authenticates the ciphertext.

---

## 6. Receive side: `multipart/signed` boundary scan

`multipart_signed_parse_content()` walks the body with `CamelMimeParser` to find
the two part offsets. When that fails, a fallback scans the raw body for the
boundary delimiter instead.

The case it exists for is a `multipart/signed` body that arrived
base64-encoded. That is malformed — RFC 2045 §6.4 permits only `7bit`, `8bit` or
`binary` on a multipart — and the parser correctly refuses to walk it. The
fallback base64-decodes a copy of the body, locates the delimiters in that copy,
and keeps it alongside the stored body.

The stored body is **not** replaced. `multipart_signed_write_to_stream_sync()`
writes the raw byte array back verbatim, so replacing it would emit a decoded
body under the original `Content-Transfer-Encoding`, corrupting the message and
its signature on any re-serialisation.

Delimiter matching follows RFC 2046 §5.1.1: `--boundary` counts only when
followed by transport padding and the end of the line, so a longer boundary that
merely starts the same way does not match.

`src/camel/tests/message/test-multipart-signed.c` covers both properties.

---

## 7. Security considerations

**What the outer signature adds.** With two layers, a party that cannot decrypt
has no way to tell whether the ciphertext is the one the sender produced. The
outer signature binds the sender's identity to the encrypted body, so the
integrity of the ciphertext can be checked without the decryption key.

**What it does not add.** It does not stop an attacker stripping the outer layer
and presenting the bare `enveloped-data` part. Whether that is noticed is a
recipient policy question, and no policy is enforced here.

**Unchanged behaviour.** Sign-only and encrypt-only paths are untouched, as is
the inner signature in both scope and construction.

**Trust.** Certificate chain validation, algorithm policy and the trust store
remain NSS's, via the user's NSS database.

---

## 8. Verification performed

Against a message generated by the patched build:

- The MIME skeleton — content types, per-part header sets, transfer encodings —
  is identical to three triple-wrapped messages, written by three different
  senders, sent from Google Workspace accounts with hosted S/MIME.
- The outer signature verifies (`openssl smime -verify`), and the bytes it
  covers are the `enveloped-data` entity alone, with no RFC822 headers.
- Decrypting yields the inner `signed-data` entity, whose signature covers the
  original `text/plain` part and, again, no RFC822 headers.
- The signed attributes present are the five listed in §5.

Triple-wrapped messages were also opened in Evolution, iOS Mail and Outlook
2016, and all three displayed them correctly. None of those three *produces*
triple-wrapped mail itself, so Evolution is unusual in emitting it — but not in
a way that gives those clients trouble reading it.

That result is why no preference is offered to turn triple-wrapping off. The
risk a preference would hedge against is a recipient whose client copes badly
with the layout, and no such client has been found. An account-wide switch
would in any case be poor insurance, since the sender cannot know which
recipients are affected until after the mail has gone.

The wrapper does not vary with the message content. A 74 KB HTML message with
images and links produces a structure identical to a short plain-text one, and
its outer signature verifies the same way, because the `enveloped-data` part is
base64 whatever it holds. Gmail therefore sees the same shape for any message,
which is why testing a single message generalises.

A message from this build was then sent to a Google Workspace recipient. It was displayed with its body intact and no attachment,
which is the behaviour the two-layer form does not get. The reply came back
from the same account and is itself triple-wrapped.

Not established:

- Whether Google documents the triple-wrap requirement anywhere official. The
  reason given in §2 is well attested by third parties, and matches the
  observed behaviour exactly, but it is not a primary source.
- Whether the clients above report the *validity* of the two signatures
  correctly. None of them warned about a bad signature, which argues against
  their rejecting it, but the security indicators were not examined
  deliberately — a client silently showing no signature status at all would
  not have been noticed.

---

## 9. Files changed

| File | Change |
| --- | --- |
| `evolution/src/composer/e-msg-composer.c` | outer sign pass in `composer_build_message_smime()` |
| `evolution-data-server/src/camel/camel-multipart-signed.c` | boundary-scan fallback |
| `evolution-data-server/src/camel/camel-smime-context.c` | `Content-Description` on the signature part |
| `evolution-data-server/src/camel/tests/message/test-multipart-signed.c` | boundary-scan tests |
