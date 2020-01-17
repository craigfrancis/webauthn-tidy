
;(function(document, window, undefined) {

	'use strict';

	function credential_create() {

		if (!('credentials2' in window.navigator)) {
			console.log('Credentials2 is not ready');
			return;
		}

		var button = this,
			output = document.getElementById(button.getAttribute('data-auth-response-id'));

		button.setAttribute('disabled', 'disabled');

		var credential_options = {
				'publicKey': {
						'rp': {
								'name': button.getAttribute('data-auth-org-name'),
								'id': button.getAttribute('data-auth-org-id')
								// 'icon': 'https://example.com/login.png'
							},
						'user': {
								'id': button.getAttribute('data-auth-user-id'),
								'name': button.getAttribute('data-auth-user-name'),
								'displayName': button.getAttribute('data-auth-user-display')
							},
						'challenge': button.getAttribute('data-auth-challenge'),
						'pubKeyCredParams': [
								{
									'type': "public-key", // As of March 2019, only "public-key" may be used.
									'alg': -7 // Elliptic curve algorithm ECDSA with SHA-256, https://www.iana.org/assignments/cose/cose.xhtml#algorithms
								}
							],
						'timeout': 10000, // In milliseconds
						'attestation': 'none', // Other options include "direct" and "indirect" - but these show the warning "Allow this site to see your security key?", saying this site "wants to see the make and model of your security key".
						'excludeCredentials': [ // Avoid creating new public key credentials (e.g. existing user who has already setup WebAuthn).
								// {
								// 	'type': "public-key",
								// 	'id': new Uint8Array(26)
								// }
							],
						'userVerification': 'discouraged'
					}
			};

		navigator.credentials2.create(credential_options).then(function(result) {

				output.value = JSON.stringify(result);
				output.form.submit();

			}).catch(function(e) {

				console.log('Error', e);

			});

	}

	function init() {

		var inputs = document.querySelectorAll('form input[data-auth-user-id]');
		for (var k = (inputs.length - 1); k >= 0; k--) {
			inputs[k].addEventListener('click', credential_create);
		}

	}

	if (document.readyState !== 'loading') {
		window.setTimeout(init); // Handle asynchronously
	} else {
		document.addEventListener('DOMContentLoaded', init);
	}

})(document, window);
