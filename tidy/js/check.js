
;(function(document, window, undefined) {

	'use strict';

	function credential_get() {

		if (!('credentials2' in window.navigator)) {
			console.log('Credentials2 is not ready');
			return;
		}

		var button = this,
			output = document.getElementById(button.getAttribute('data-auth-response-id'));

		button.setAttribute('disabled', 'disabled');

		var credentials = button.getAttribute('data-auth-key-ids').split('|'); // Rough way to support multiple ID's
		for (var k = (credentials.length - 1); k >= 0; k--) {
			credentials[k] = {'type': 'public-key', 'id': credentials[k]};
		}

		var credential_options = {
				'publicKey': {
						'rpId': button.getAttribute('data-auth-org-id'),
						'challenge': button.getAttribute('data-auth-challenge'),
						'timeout': 10000, // In milliseconds
						'allowCredentials': credentials,
						'userVerification': 'discouraged'
					}
			};

		navigator.credentials2.get(credential_options).then(function(result) {

				output.value = JSON.stringify(result);
				output.form.submit();

			}).catch(function(e) {

				console.log('Error', e);

			});

	}

	function init() {

		var inputs = document.querySelectorAll('form input[data-auth-key-ids]');
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
