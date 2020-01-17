
# WebAuthn Cleanup

Experimenting with making WebAuthn easier to use.

Primarily trying to avoid **CBOR** encoding.

And providing the binary data in base64 encoding for easy transport to the server - rather than Uint8Array/ArrayBuffer, or the less well supported base64url (aka rfc4648).

[Discussion](https://github.com/w3c/webauthn/issues/1362)
