
# WebAuthn Cleanup

Experimenting with making WebAuthn easier to use.

Primarily trying to avoid **CBOR** encoding.

And providing the binary data in base64 encoding for easy transport to the server - rather than Uint8Array/ArrayBuffer, or the less well supported base64url (aka rfc4648).

[Discussion](https://github.com/w3c/webauthn/issues/1362)

---

## HTML

If the browser could implement this JavaScript:

https://github.com/craigfrancis/webauthn-tidy/blob/master/html/js/webauthn.js

Then the HTML and Server side code would be considerably easier:

- [Create](https://github.com/craigfrancis/webauthn-tidy/blob/master/html/create.php)
- [Check](https://github.com/craigfrancis/webauthn-tidy/blob/master/html/check.php)

---

If not, then
