<?php

//--------------------------------------------------
// Config

	$host = preg_replace('/[^a-z0-9\.]/', '', ($_SERVER['HTTP_HOST'] ?? ''));
	$uri = ($_SERVER['REQUEST_URI'] ?? '');
	$origin = 'https://' . $host;

	$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

	header("Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action " . $origin . $uri . "; img-src " . $origin . "; script-src " . $origin . "/js/; frame-ancestors 'none'; block-all-mixed-content;");
	header("Feature-Policy: accelerometer 'none'; autoplay 'none'; camera 'none'; document-domain 'none'; encrypted-media 'none'; focus-without-user-activation 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; usb 'none'; xr-spatial-tracking 'none'; sync-xhr 'none'; picture-in-picture 'none';");

	session_start();

//--------------------------------------------------
// Auth details

	$create_auth = ($_SESSION['create_auth'] ?? ''); // Only for debugging.

	$user_key_id = ($_SESSION['user_key_id'] ?? '');
	$user_key_public = ($_SESSION['user_key_public'] ?? '');

	if (!$user_key_id) {
		exit('Missing user key id in session.');
	}

	if (!$user_key_public) {
		exit('Missing user key public in session.');
	}

//--------------------------------------------------
// Challenge

	if ($method == 'GET') {

		$challenge = random_bytes(32);

		$_SESSION['check_challenge'] = $challenge;

	} else {

		$challenge = ($_SESSION['check_challenge'] ?? '');

	}

//--------------------------------------------------
// If submitted

	$errors = [];

	if (isset($_POST['auth_json'])) {

		//--------------------------------------------------
		// Parse

			$check_auth = json_decode($_POST['auth_json'], true);

		//--------------------------------------------------
		// Client data

			$client_data = base64_decode($check_auth['response']['client_base64']);

			$check_auth['response']['client'] = json_decode($client_data, true);

		//--------------------------------------------------
		// Auth data

			$auth_data = base64_decode($check_auth['response']['auth_base64']);

		//--------------------------------------------------
		// Checks basic

			if (($check_auth['id'] ?? '') !== $user_key_id) {
				$errors[] = 'Returned type is not for the same id.';
			}

			if (($check_auth['type'] ?? '') !== 'public-key') {
				$errors[] = 'Returned type is not a "public-key".';
			}

			if (($check_auth['response']['client']['type'] ?? '') !== 'webauthn.get') {
				$errors[] = 'Returned type is not "webauthn.get".';
			}

			if (($check_auth['response']['client']['origin'] ?? '') !== $origin) {
				$errors[] = 'Returned origin is not "' . $origin . '".';
			}

		//--------------------------------------------------
		// Check challenge

			$response_challenge = ($check_auth['response']['client']['challenge'] ?? '');
			$response_challenge = base64_decode(strtr($response_challenge, '-_', '+/'));

			if (!$challenge) {
				$errors[] = 'The challenge has not been stored in the session.';
			} else if (substr_compare($response_challenge, $challenge, 0) !== 0) {
				$errors[] = 'The challenge has changed.';
			}

		//--------------------------------------------------
		// Check signature

			$signature = ($check_auth['response']['signature_base64'] ?? '');
			if ($signature) {
				$signature = base64_decode($signature);
			}

			if (!$signature) {
				$errors[] = 'No signature returned.';
			}

		//--------------------------------------------------
		// Check

			if (count($errors) == 0) {

				$key_public = openssl_pkey_get_public($user_key_public);

				if ($key_public === false) {

					$errors[] = 'Public key invalid.';

				} else {

					$verify_data  = '';
					$verify_data .= $auth_data;
					$verify_data .= hash('sha256', $client_data, true); // Contains the $challenge

					if (openssl_verify($verify_data, $signature, $key_public, OPENSSL_ALGO_SHA256) === 1) {
						$errors[] = 'Success!';
					} else {
						$errors[] = 'Invalid signature.';
					}

				}

			}

		//--------------------------------------------------
		// Show errors

			header('Content-Type: text/plain; charset=UTF-8');

			echo "\n--------------------------------------------------\n\n";
			print_r($errors);
			echo "\n--------------------------------------------------\n\n";
			print_r($user_key_public);
			echo "\n--------------------------------------------------\n\n";
			print_r(base64_encode($challenge) . "\n");
			echo "\n--------------------------------------------------\n\n";
			print_r($check_auth);
			echo "\n--------------------------------------------------\n\n";
			print_r($create_auth);
			echo "\n--------------------------------------------------\n\n";
			exit();

	}

?>
<!DOCTYPE html>
<html lang="en-GB" xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta charset="UTF-8" />
	<title>Check</title>
	<script src="./js/webauthn-tidy.js" async="async"></script>
	<script src="./js/webauthn-check.js" async="async"></script>
</head>
<body>

	<h2>Stored Key ID</h2>
	<p><pre><?= htmlentities($user_key_id) ?></pre></p>

	<h2>Stored Key Public</h2>
	<p><pre><?= htmlentities($user_key_public) ?></pre></p>

	<h2>Check Details</h2>
	<form action="<?= htmlentities($uri) ?>" method="post" accept-charset="UTF-8">

		<input
			type="button"
			value="Check"
			data-auth-org-id="<?= htmlentities($host) ?>"
			data-auth-key-ids="<?= htmlentities(implode('|', [$user_key_id ?? ''])) ?>"
			data-auth-challenge="<?= htmlentities(base64_encode($challenge)) ?>"
			data-auth-response-id="auth_response" />

		<input type="hidden" name="auth_json" value="" id="auth_response" />

	</form>

</body>
</html>