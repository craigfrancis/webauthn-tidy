
;(function(document, window, undefined) {

	//--------------------------------------------------
	// Checks

		'use strict';

		if (!('Uint8Array' in window) || !('credentials' in window.navigator)) {
			return;
		}

	//--------------------------------------------------
	// Conversion functions

		function base64_to_uint8array(base64) { // https://stackoverflow.com/a/21797381/6632

			var binary = window.atob(base64),
				array = new Uint8Array(new ArrayBuffer(binary.length));

			for (var k = (binary.length - 1); k >= 0; k--) {
				array[k] = binary.charCodeAt(k);
			}

			return array;

		}

		function buffer_to_base64(buffer) {
			var uint8array = new Uint8Array(buffer);
			return window.btoa(String.fromCharCode.apply(null, uint8array));
		}

	//--------------------------------------------------
	// Get

		function credential_get(e) {

			e.preventDefault();

			var button = this,
				options = button.getAttribute('data-webauthn-get');

			button.setAttribute('disabled', 'disabled');

			options = JSON.parse(options);
			options['publicKey']['challenge'] = base64_to_uint8array(options['publicKey']['challenge']);

			for (var k = (options['publicKey']['allowCredentials'].length - 1); k >= 0; k--) {
				options['publicKey']['allowCredentials'][k]['id'] = base64_to_uint8array(options['publicKey']['allowCredentials'][k]['id']);
			}

			navigator.credentials.get(options).then(function(result) {

					//--------------------------------------------------
					// Make result JSON friendly.

						var output = {
								'id':                result.id.replace(/-/g, '+').replace(/_/g, '/'), // Use normal base64, not base64url (rfc4648)
								'type':              result.type,
								'clientDataJSON':    buffer_to_base64(result.response.clientDataJSON),
								'authenticatorData': buffer_to_base64(result.response.authenticatorData),
								'signature':         buffer_to_base64(result.response.signature)
							};

					//--------------------------------------------------
					// Complete

						var input = document.createElement('input');
						input.setAttribute('type', 'hidden');
						input.setAttribute('name', button.getAttribute('name'));
						input.setAttribute('value', JSON.stringify(output));

						button.parentNode.insertBefore(input, button);

						button.setAttribute('name', '');
						button.form.submit();

				}).catch(function(e) {

					button.removeAttribute('disabled');

					console.log('Error', e);

				});

		}

	//--------------------------------------------------
	// Setup

		function init() {

			var inputs = document.querySelectorAll('form input[data-webauthn-get]');
			for (var k = (inputs.length - 1); k >= 0; k--) {
				inputs[k].addEventListener('click', credential_get);
			}

		}

		if (document.readyState !== 'loading') {
			window.setTimeout(init); // Handle asynchronously
		} else {
			document.addEventListener('DOMContentLoaded', init);
		}

})(document, window);
