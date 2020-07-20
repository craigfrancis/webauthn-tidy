<?php

//--------------------------------------------------
// Config

	$host = preg_replace('/[^a-z0-9\.]/', '', ($_SERVER['HTTP_HOST'] ?? ''));
	$uri = ($_SERVER['REQUEST_URI'] ?? '');
	$origin = 'https://' . $host;
	$algorithm = -7; // Elliptic curve algorithm ECDSA with SHA-256, https://www.iana.org/assignments/cose/cose.xhtml#algorithms

	$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

	header("Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action " . $origin . $uri . "; img-src " . $origin . "; script-src " . $origin . "/html/js/; frame-ancestors 'none'; block-all-mixed-content;");
	header("Feature-Policy: accelerometer 'none'; autoplay 'none'; camera 'none'; document-domain 'none'; encrypted-media 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; usb 'none'; xr-spatial-tracking 'none'; sync-xhr 'none'; picture-in-picture 'none';");

	session_start();

//--------------------------------------------------
// Challenge

	if ($method == 'GET') {
		$_SESSION['challenge'] = random_bytes(32);
	}

	$challenge = ($_SESSION['challenge'] ?? '');

//--------------------------------------------------
// Auth details

	$create_auth = ($_SESSION['webauthn_data_create'] ?? ''); // Only for debugging.

	$user_key_id = ($_SESSION['user_key_id'] ?? '');
	$user_key_value = ($_SESSION['user_key_value'] ?? '');

	if (!$user_key_id) {
		exit('Missing user key id in session.');
	}

	if (!$user_key_value) {
		exit('Missing user key value in session.');
	}

//--------------------------------------------------
// If submitted

	$errors = [];

	if (isset($_POST['auth'])) {

		//--------------------------------------------------
		// Parse

			$webauthn_data = json_decode($_POST['auth'], true);

		//--------------------------------------------------
		// Client data

			$client_data_json = base64_decode($webauthn_data['response']['clientDataJSON']);

			$client_data = json_decode($client_data_json, true);

		//--------------------------------------------------
		// Auth data

			$auth_data = base64_decode($webauthn_data['response']['authenticatorData']);

		//--------------------------------------------------
		// Checks basic

			if (($webauthn_data['id'] ?? '') !== $user_key_id) {
				$errors[] = 'Returned type is not for the same id.';
			}

			if (($webauthn_data['type'] ?? '') !== 'public-key') {
				$errors[] = 'Returned type is not a "public-key".';
			}

			if (($client_data['type'] ?? '') !== 'webauthn.get') {
				$errors[] = 'Returned type is not "webauthn.get".';
			}

			if (($client_data['origin'] ?? '') !== $origin) {
				$errors[] = 'Returned origin is not "' . $origin . '".';
			}

			if (!hash_equals(hash('sha256', $host), ($webauthn_data['auth']['rpIdHash'] ?? ''))) {
				$errors[] = 'The Relying Party ID hash is not the same.';
			}

		//--------------------------------------------------
		// Check challenge

			$response_challenge = ($client_data['challenge'] ?? '');
			$response_challenge = base64_decode(strtr($response_challenge, '-_', '+/'));

			if (!$challenge) {
				$errors[] = 'The challenge has not been stored in the session.';
			} else if (substr_compare($response_challenge, $challenge, 0) !== 0) {
				$errors[] = 'The challenge has changed.';
			}

		//--------------------------------------------------
		// Check signature

			$signature = ($webauthn_data['response']['signature'] ?? '');
			if ($signature) {
				$signature = base64_decode($signature);
			}

			if (!$signature) {
				$errors[] = 'No signature returned.';
			}

		//--------------------------------------------------
		// Key

			$key_info = NULL;

			if (count($errors) == 0) {

				$key_ref = openssl_pkey_get_public($user_key_value);

				if ($key_ref === false) {

					$errors[] = 'Public key invalid.';

				} else {

					$key_info = openssl_pkey_get_details($key_ref);

					if ($key_info['type'] == OPENSSL_KEYTYPE_EC) {

						if ($key_info['ec']['curve_oid'] != '1.2.840.10045.3.1.7') {
							$errors[] = 'Invalid public key curve identifier';
						}

					} else {

						$errors[] = 'Unknown public key type (' . $key_info['type'] . ')';

					}

				}

			}

		//--------------------------------------------------
		// Check

			if (count($errors) == 0) {

				$verify_data  = '';
				$verify_data .= $auth_data;
				$verify_data .= hash('sha256', $client_data_json, true); // Contains the $challenge

				if (openssl_verify($verify_data, $signature, $key_ref, OPENSSL_ALGO_SHA256) === 1) {
					$errors[] = 'Success!';
				} else {
					$errors[] = 'Invalid signature.';
				}

			}

		//--------------------------------------------------
		// Show errors

			header('Content-Type: text/plain; charset=UTF-8');

			echo "\n--------------------------------------------------\n\n";
			print_r($errors);
			echo "\n--------------------------------------------------\n\n";
			echo 'Sign Count: ' . ($webauthn_data['auth']['signCount'] ?? 0) . "\n";
			echo "\n--------------------------------------------------\n\n";
			print_r($user_key_value);
			echo "\n";
			echo "\n--------------------------------------------------\n\n";
			print_r(base64_encode($challenge) . "\n");
			echo "\n--------------------------------------------------\n\n";
			print_r($webauthn_data);
			print_r($client_data);
			echo "\n--------------------------------------------------\n\n";
			print_r($create_auth);
			echo "\n--------------------------------------------------\n\n";
			exit();

	}

//--------------------------------------------------
// Request

	$request = [
			'publicKey' => [
					'rpId' => $host,
					'challenge' => base64_encode($challenge),
					'timeout' => 10000, // In milliseconds
					'allowCredentials' => [
							[
								'type' => 'public-key',
								'id' => $user_key_id,
							],
						],
					'userVerification' => 'discouraged'
				],
		];

?>
<!DOCTYPE html>
<html lang="en-GB" xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta charset="UTF-8" />
	<title>Check</title>
	<script src="./js/webauthn.js" async="async"></script>
</head>
<body>

	<h2>Stored Key ID</h2>
	<p><pre><?= htmlentities($user_key_id) ?></pre></p>

	<h2>Stored Key Value</h2>
	<p><pre><?= htmlentities($user_key_value) ?></pre></p>

	<h2>Check Details</h2>
	<form action="<?= htmlentities($uri) ?>" method="post" accept-charset="UTF-8">

		<input type="submit" name="auth" value="Check" data-webauthn-get="<?= htmlentities(json_encode($request)) ?>" />

	</form>

</body>
</html>