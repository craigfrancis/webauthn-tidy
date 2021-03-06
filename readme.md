
# WebAuthn Cleanup

Experimenting with making WebAuthn easier to use:

- Converting Uint8Array/ArrayBuffer values to base64, so that data can be easily sent to/from the server.

- Providing the public key in DER format, similar to PEM, as many systems can use this directly.

- Providing the `flags` and `signCount` in an easy to read format.

- Avoiding CBOR decoding (few systems support this).

- Avoiding the `attestedCredentialData` length issue, where mistakes are easily made.

- Using normal base64 encoding (where possible), rather than the less common base64url (rfc4648).

- Potentially making a version that could be done in HTML only (without JavaScript).

[Discussion](https://github.com/w3c/webauthn/issues/1362)

---

## HTML

If the browser could implement something like this JavaScript to provide a [way to use WebAuthn without Javascript](https://github.com/w3c/webauthn/issues/1255):

https://github.com/craigfrancis/webauthn-tidy/blob/main/html/js/webauthn.js?ts=4

Then the HTML and Server side code would be considerably easier:

- [Create](https://github.com/craigfrancis/webauthn-tidy/blob/main/html/create.php?ts=4)
- [Check](https://github.com/craigfrancis/webauthn-tidy/blob/main/html/check.php?ts=4)

---

## API Version 2

While no browsers currently support this, there is a new "[getPublicKey()](https://github.com/w3c/webauthn/issues/1363)" method.

- [Create](https://github.com/craigfrancis/webauthn-tidy/blob/main/new/create.php?ts=4)
- [Check](https://github.com/craigfrancis/webauthn-tidy/blob/main/new/check.php?ts=4)

---

## API Alternative

If not, then this JS will make an easier to use `window.navigator.credentials2`:

https://github.com/craigfrancis/webauthn-tidy/blob/main/tidy/js/tidy.js?ts=4

So individual websites will find it easier to implement in their:

- Create [HTML](https://github.com/craigfrancis/webauthn-tidy/blob/main/tidy/create.php?ts=4) and [JS](https://github.com/craigfrancis/webauthn-tidy/blob/main/tidy/js/create.js?ts=4)
- Check [HTML](https://github.com/craigfrancis/webauthn-tidy/blob/main/tidy/check.php?ts=4) and [JS](https://github.com/craigfrancis/webauthn-tidy/blob/main/tidy/js/check.js?ts=4)
