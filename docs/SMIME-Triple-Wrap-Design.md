# S/MIME Triple-Wrap Design for Evolution / Evolution-Data-Server

## 1. Scope and goals

This document explains how Evolution and Evolution-Data-Server (EDS) currently implement S/MIME, and how the proposed Triple-Wrap (RFC 2634 + RFC 5035) changes fit into that design.

It is written to:
- Help reason about security properties and threat models.
- Provide a defensible design narrative for maintainers and reviewers.
- Serve as a map back to specific source files and functions.

This is **not** a full S/MIME tutorial; it focuses on:
- The **send** path for S/MIME sign / encrypt, and
- The additional logic required to produce **Gmail/Broadcom-compatible triple-wrapped** messages.

Key references:
- Project context: `SMIME_Implementation_Context.md`
- RFC 2634: Enhanced Security Services for S/MIME (triple wrapping)
- RFC 5035: ESS update, SigningCertificateV2 / ESSCertIDv2 (SHA-256)
- EID 6562: Clarification on first certificate in signing-certificate attributes

---

## 2. Architecture overview

### 2.1 Evolution vs Evolution-Data-Server roles

**Evolution (UI / composer)**

- Handles user interaction and message composition.
- Decides **whether** to sign and/or encrypt.
- Assembles a MIME tree (`CamelMimePart` hierarchy) for the outgoing message.
- For S/MIME, delegates cryptographic operations (sign / encrypt / decrypt / verify) to Camel in EDS.

Relevant file:
- `evolution/src/composer/e-msg-composer.c`
  - `composer_build_message_smime()`: attaches S/MIME signing and encryption to the composed message.

**Evolution-Data-Server (Camel + NSS)**

- Implements the mail engine and S/MIME plumbing.
- Exposes abstract crypto APIs via `CamelCipherContext`:
  - `camel_cipher_context_sign_sync()`
  - `camel_cipher_context_encrypt_sync()`
  - `camel_cipher_context_decrypt_sync()`
  - `camel_cipher_context_verify_sync()`
- Provides an S/MIME implementation (`CamelSMIMEContext`) backed by **NSS** (Network Security Services).

Relevant files:
- `evolution-data-server/src/camel/camel-cipher-context.[ch]`
- `evolution-data-server/src/camel/camel-smime-context.[ch]`

**NSS (Crypto / CMS layer)**

- Handles CMS/PKCS#7 structures, certificate / key operations, and crypto primitives.
- EDS uses NSS APIs such as:
  - `NSS_CMSMessage_Create`
  - `NSS_CMSSignedData_Create`
  - `NSS_CMSEnvelopedData_Create`
  - `NSS_CMSSignerInfo_Create` and attribute helpers.

---

## 3. Current S/MIME send behaviour (pre-Triple-Wrap)

This section describes how Evolution+EDS behave **before** adding Triple-Wrap.

### 3.1 High-level flows

**Sign-only (S/MIME)**

1. Composer builds a MIME tree for the message body.
2. `composer_build_message_smime()` sees `context->smime_sign == TRUE`, `context->smime_encrypt == FALSE`.
3. It creates a `CamelSMIMEContext` and calls:
   - `camel_cipher_context_sign_sync()`
4. Inside Camel:
   - `camel_cipher_context_sign_sync()` dispatches to `smime_context_sign_sync()` in `camel-smime-context.c`.
   - `smime_context_sign_sync()` calls `sm_signing_cmsmessage()` to build an NSS `NSSCMSSignedData`.
5. Depending on `CamelSMIMEContextPrivate::sign_mode`:
   - **CLEARSIGN** (`CAMEL_SMIME_SIGN_CLEARSIGN`):
     - Output is `multipart/signed`:
       - First part: original MIME content.
       - Second part: `application/pkcs7-signature` containing CMS `signedData`.
   - **ENVELOPED SIGN** (`CAMEL_SMIME_SIGN_ENVELOPED`):
     - Output is opaque: `application/pkcs7-mime; smime-type=signed-data`.

**Encrypt-only (S/MIME)**

1. Composer sets `context->smime_encrypt == TRUE`, `context->smime_sign == FALSE`.
2. It creates a `CamelSMIMEContext` and calls:
   - `camel_cipher_context_encrypt_sync()`
3. `smime_context_encrypt_sync()`:
   - Resolves recipient certificates (using Camel session + NSS).
   - Builds `NSSCMSEnvelopedData` over the canonicalized message content.
   - Encodes to `application/pkcs7-mime; smime-type=enveloped-data` with filename `smime.p7m`.

**Sign + Encrypt (S/MIME)**

Today, the implementation effectively does:

1. **Sign once**, usually using `CAMEL_SMIME_SIGN_ENVELOPED` (opaque signed-data):
   - Output: `application/pkcs7-mime; smime-type=signed-data`.
2. **Encrypt that result**:
   - Input: opaque signed-data part.
   - Output: `application/pkcs7-mime; smime-type=enveloped-data` (final message).

This is a **Sign-then-Encrypt** layout, but **only two layers**:
- There is **no outer signature** over the encrypted blob.

### 3.2 Key data structures and functions

**In Evolution**

- `e-msg-composer.c`:
  - `composer_build_message_smime(AsyncContext *context, GCancellable *cancellable, GError **error)`:
    - Queries account's S/MIME settings (`ESourceSMIME`).
    - Determines `signing_certificate`, `encryption_certificate`, `signing_algorithm`.
    - Sets up `CamelSMIMEContext`:
      - `camel_smime_context_set_sign_mode()`:
        - For sign+encrypt, it uses `CAMEL_SMIME_SIGN_ENVELOPED` (opaque signed-data).
      - `camel_smime_context_set_encrypt_key()`:
        - Configures recipient/encrypt-to-self options.
    - Calls:
      - `camel_cipher_context_sign_sync()` (if signing).
      - `camel_cipher_context_encrypt_sync()` (if encrypting).

**In Evolution-Data-Server (Camel S/MIME)**

- `camel-smime-context.c`:
  - `sm_signing_cmsmessage()`:
    - Takes `CamelSMIMEContext *context`, signer nickname (`nick`), hash algorithm (`SECOidTag *hash`), and a `detached` flag.
    - Uses NSS to:
      - Find the signer certificate (`CERT_FindUserCertByUsage`).
      - Select hash algorithm (defaulted from `cert->signature` if caller passed `SEC_OID_UNKNOWN`).
      - Create `NSSCMSMessage` and `NSSCMSSignedData`.
      - Set `contentInfo` to `id-data` (with or without detached content).
      - Create `NSSCMSSignerInfo`, attach cert chain and `signingTime` attribute.
    - Returns a fully-built `NSSCMSMessage *` for signing.
  - `smime_context_sign_sync()`:
    - Canonicalizes the input MIME part (line endings, From-escaping).
    - Feeds that into an NSS CMS encoder (`NSS_CMSEncoder_Start/Update/Finish`).
    - Wraps the encoder output in a `CamelDataWrapper`.
    - If `sign_mode == CLEARSIGN`, builds `multipart/signed` with:
      - `micalg` derived from hash (`sha1`, `sha-256`, etc.).
      - `protocol` equal to the S/MIME signature protocol (PKCS#7).
    - Otherwise, outputs opaque `application/pkcs7-mime; smime-type=signed-data`.
  - `smime_context_encrypt_sync()`:
    - Resolves recipient certificates.
    - Calls `NSS_CMSMessage_Create`, `NSS_CMSEnvelopedData_Create`, `NSS_CMSContentInfo_SetContent_Data`.
    - Generates a bulk key and encrypts the canonicalized content.
    - Outputs `application/pkcs7-mime; smime-type=enveloped-data`.

---

## 4. Triple-Wrap requirements (RFC 2634 / RFC 5035)

### 4.1 RFC 2634 triple-wrap structure

RFC 2634 defines **triple wrapping** as: **sign → encrypt → sign again**.

Steps (simplified):

1. Start with the original content + inner MIME headers.
2. **Inner sign**:
   - Create CMS `signedData` over the inner content.
   - Represent it either as `multipart/signed` or `application/pkcs7-mime; smime-type=signed-data`.
3. **Encrypt**:
   - Encrypt the entire result of step 2 as `application/pkcs7-mime; smime-type=enveloped-data`.
4. **Outer sign**:
   - Sign the result of step 3 **including its MIME headers**.
   - Produce an outer `multipart/signed` or `application/pkcs7-mime` (outer signature).
   - The **outer signature** binds attributes (e.g., security labels, policy info) to the **encrypted body**, and is what intermediate agents can see/act on.

For **our Gmail/Broadcom use-case**, the target is:

- Outer layer: `multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"`.
- Middle: `application/pkcs7-mime; smime-type=enveloped-data` (encrypted inner structure).
- Inner: original signed content (signed-data, possibly in opaque form).

### 4.2 RFC 5035 and SHA-256

RFC 5035 updates ESS to make the **"signing certificate"** attribute algorithm-agile:

- Original ESS used **ESSCertID** hard-wired to **SHA-1**.
- RFC 5035 introduces:
  - **ESSCertIDv2**
  - **SigningCertificateV2** attribute
- Hash algorithm:
  - For SHA-1, `SigningCertificate` is used.
  - For SHA-256 and others, `SigningCertificateV2` with `ESSCertIDv2` is required.

For compatibility with modern Gmail/Broadcom deployments:

- The **outer signature** should:
  - Use **SHA-256** as the digest algorithm.
  - Include a **SigningCertificateV2** attribute referring to the signer's certificate via SHA-256 hash.
  - Ensure the signer's cert is the **first** entry in the sequence (per EID 6562).

Exactly how much of this NSS does automatically vs. requires manual attribute construction is an implementation detail, but the design goal is clear: **outer signature must be clearly, unambiguously tied to the signer's cert using SHA-256**.

---

## 5. Proposed Triple-Wrap design

### 5.1 Goals and non-goals

**Goals**

- For outgoing S/MIME messages that are both **signed and encrypted**, produce a **triple-wrapped** structure as per RFC 2634, such that:
  - Gmail/Broadcom can **verify the outer signature** and
  - **decrypt** the inner envelope to display the plaintext inline (no unusable `smime.p7m` attachment).
- Use **SHA-256** for the outer signature and expose a SigningCertificateV2 / ESSCertIDv2 structure consistent with RFC 5035.
- Minimize API surface changes:
  - Prefer using existing `CamelCipherContext` APIs, and localizing Triple-Wrap orchestration in the Evolution composer.

**Non-goals (initial phase)**

- Fully re-architecting the S/MIME/NSS integration.
- Changing how sign-only or encrypt-only modes behave.
- Comprehensive receive-side refactor (beyond ensuring basic compatibility with triple-wrapped messages).

### 5.2 Send path changes (high-level)

For messages where the user selects **both** S/MIME sign and S/MIME encrypt:

1. **Inner sign (existing behaviour)**  
   - `composer_build_message_smime()`:
     - Creates `CamelSMIMEContext` A.
     - Sets `sign_mode = CAMEL_SMIME_SIGN_ENVELOPED` (opaque `signed-data`).
     - Calls `camel_cipher_context_sign_sync()` on the original MIME tree.
   - Output: `application/pkcs7-mime; smime-type=signed-data` (inner signature).

2. **Encrypt (existing behaviour)**  
   - Same function uses `CamelSMIMEContext` B (or reuses the context as appropriate).
   - Calls `camel_cipher_context_encrypt_sync()` with recipients.
   - Output: `application/pkcs7-mime; smime-type=enveloped-data` (encrypted blob).

3. **Outer sign (new Triple-Wrap step)**  
   - Create `CamelSMIMEContext` C for the **outer signature**.
   - Configure C:
     - `sign_mode = CAMEL_SMIME_SIGN_CLEARSIGN` so the result is `multipart/signed`.
     - Digest algorithm: **explicitly set to SHA-256**.
   - Treat the encrypted MIME part (`application/pkcs7-mime; smime-type=enveloped-data`) plus its headers as the sign input.
   - Call `camel_cipher_context_sign_sync()` to produce:
     - A `multipart/signed` outer structure:
       - Part 1: the encrypted body (unchanged).
       - Part 2: `application/pkcs7-signature` outer signature with `micalg=sha-256`.
   - Replace the message's top-level content with this outer `multipart/signed` part.

Resulting structure:

- `multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"`
  - Part 1: `application/pkcs7-mime; smime-type=enveloped-data` (encrypted inner signed content)
  - Part 2: `application/pkcs7-signature` (outer CMS signedData over Part 1)

### 5.3 Where the logic lives

**Evolution (composer)**

- Orchestration of the three passes lives in `composer_build_message_smime()`:
  - This function already has access to:
    - S/MIME account settings (`ESourceSMIME`).
    - The intermediate `CamelMimePart` tree (`context->top_level_part` and `context->message`).
  - It is the natural place to:
    - Decide "Triple-Wrap or not" (only when both sign and encrypt are selected).
    - Invoke sign → encrypt → outer sign in sequence.

**Evolution-Data-Server (Camel)**

- No new public API is strictly required:
  - `CamelCipherContext` already supports:
    - Clearsign S/MIME (`multipart/signed`).
    - Opaque signed-data (`application/pkcs7-mime; smime-type=signed-data`).
    - Enveloped-data encryption (`application/pkcs7-mime; smime-type=enveloped-data`).
- Possible localized Camel changes:
  - Ensure that when **SHA-256** is used:
    - The `micalg` parameter for `multipart/signed` is exactly what broad clients expect (e.g., `sha-256`).
  - Confirm or extend NSS integration so:
    - `SigningCertificateV2` / `ESSCertIDv2` is present for SHA-256 signatures.
    - The signer's cert is first in the ESSCertIDv2 sequence (per EID 6562).
- **Implementation note:** The initial Triple-Wrap implementation uses NSS as-is for the outer signature (SHA-256 digest, multipart/signed, micalg=sha-256). NSS may add signing-certificate attributes internally. If Gmail/Broadcom still reject messages in testing, add an explicit SigningCertificateV2 attribute in `sm_signing_cmsmessage()` (e.g. via NSS API if available, or by encoding the RFC 5035 attribute).

---

## 6. Security considerations

### 6.1 Why Triple-Wrap improves security (and Gmail compatibility)

The main issues with the existing **Sign-then-Encrypt** (two-layer) approach are:

- The **inner signature** is over **plaintext**, but:
  - After encryption, intermediate agents—and Gmail's Efail mitigation—only see the **encrypted blob**.
  - They cannot tell whether the blob is unchanged or whether an attacker tampered with envelope headers or structure.
- Some clients (including Gmail/Broadcom in your testing context) require an **outer cryptographic seal**:
  - The outer signature must be over the **encrypted body** itself.
  - This allows them to:
    - Validate integrity of the encrypted content, and
    - Make safe decisions about when to decrypt and render inline.

Triple-Wrap addresses this by:

- Binding sender identity and attributes **both** to:
  - The original plaintext (inner signature), and
  - The encrypted body (outer signature).
- Providing **defence against malleability / Efail-style attacks** where:
  - Attacker splices encrypted bodies or alters surrounding structures without access to keys.

### 6.2 Assumptions

- NSS correctly:
  - Validates certificate chains for `signerInfo`.
  - Enforces algorithms and key sizes in line with policy.
- Certificate store:
  - Is managed by the underlying OS/user trust policy (NSS database).
  - Trusted roots and intermediate CAs are appropriately configured.
- Evolution/EDS do not override critical NSS error states (e.g., bad signatures, untrusted roots) in a way that would mislead users.

### 6.3 Compatibility and downgrade risks

- **Other S/MIME clients**:
  - Triple-Wrap is standards-based; conformant clients should:
    - Verify outer signature (optional).
    - Decrypt inner envelope.
    - Verify inner signature.
  - Some older or simpler clients may ignore the outer signature and only process inner layers; the message remains decryptable.
- **Downgrade scenarios**:
  - An attacker who can strip the outer signature and `multipart/signed` layer might try to present just the encrypted inner `smime.p7m` part.
  - This is largely a client UX question:
    - Our design does not prevent such stripping, but:
      - The intended major gain is that **security-aware clients** (Gmail/Broadcom) refuse to decrypt unless the outer signature is present and valid.

---

## 7. Testing strategy (high-level)

### 7.1 Positive cases

- **Local round-trip**:
  - Send a triple-wrapped message from Evolution (Triple-Wrap build) to another S/MIME-capable Evolution.
  - Verify:
    - Outer signature validates.
    - Message decrypts.
    - Inner signature validates.
- **Gmail/Broadcom compatibility**:
  - Send signed+encrypted mail to a Gmail account.
  - Check:
    - Body is visible **inline** (no unusable `smime.p7m` attachment).
    - Gmail's UI indicates the message is signed/encrypted as expected.

### 7.2 Negative and corner cases

- **Tampered outer signature**:
  - Modify the outer `application/pkcs7-signature`.
  - Client should refuse to validate the outer signature; Gmail should decline to decrypt.
- **Missing outer signature**:
  - Fall back to current behavior (Sign-then-Encrypt without outer sign).
  - Confirm Gmail still exhibits the original "p7m attachment" behavior; this demonstrates the improvement from Triple-Wrap.
- **Multiple recipients / mixed capabilities**:
  - Recipients with:
    - Full S/MIME support (should work).
    - Limited support (may ignore outer signature but still decrypt).

---

## 8. Summary

- Evolution and EDS already implement **sign** and **encrypt** using `CamelSMIMEContext` and NSS CMS primitives.
- The current sign+encrypt flow is a two-step **Sign-then-Encrypt** without an outer signature, which is insufficient for some security-hardened clients (notably Gmail/Broadcom) that expect an RFC 2634 triple-wrap.
- The proposed design:
  - Adds an **outer clearsign step** (multipart/signed, SHA-256) **after** encryption.
  - Keeps Triple-Wrap orchestration inside the **Evolution composer**, relying on existing Camel/NSS APIs.
  - Aligns with RFC 2634 for triple wrapping and RFC 5035 for SHA-256 certificate identification.
- This document provides the architectural and security rationale needed to defend the design in reviews and to maintain it over time.
