
# WebAuthn Cleanup

Experimenting with making WebAuthn easier to use.

Primarily trying to avoid **CBOR** encoding.

And providing the binary data in base64 encoding for easy transport to the server - rather than Uint8Array/ArrayBuffer, or the less well supported base64url (aka rfc4648).

[Discussion](https://github.com/w3c/webauthn/issues/1362)

---

## HTML

If the browser could implement something like this JavaScript to provide a [way to use WebAuthn without Javascript](https://github.com/w3c/webauthn/issues/1255):

https://github.com/craigfrancis/webauthn-tidy/blob/master/html/js/webauthn.js?ts=4

Then the HTML and Server side code would be considerably easier:

- [Create](https://github.com/craigfrancis/webauthn-tidy/blob/master/html/create.php?ts=4)
- [Check](https://github.com/craigfrancis/webauthn-tidy/blob/master/html/check.php?ts=4)

---

## API Alternative

If not, then this JS will make an easier to use `window.navigator.credentials2`:

https://github.com/craigfrancis/webauthn-tidy/blob/master/tidy/js/tidy.js?ts=4

So individual websites will find it easier to implement in their:

- Create [HTML](https://github.com/craigfrancis/webauthn-tidy/blob/master/tidy/create.php?ts=4) and [JS](https://github.com/craigfrancis/webauthn-tidy/blob/master/tidy/js/create.js?ts=4)
- Check [HTML](https://github.com/craigfrancis/webauthn-tidy/blob/master/tidy/check.php?ts=4) and [JS](https://github.com/craigfrancis/webauthn-tidy/blob/master/tidy/js/check.js?ts=4)
