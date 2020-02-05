<?php

//--------------------------------------------------
// Config

	$host = preg_replace('/[^a-z0-9\.]/', '', ($_SERVER['HTTP_HOST'] ?? ''));
	$uri = ($_SERVER['REQUEST_URI'] ?? '');
	$origin = 'https://' . $host;
	$algorithm = -7; // Elliptic curve algorithm ECDSA with SHA-256, https://www.iana.org/assignments/cose/cose.xhtml#algorithms

	$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

	header("Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action " . $origin . $uri . "; img-src " . $origin . "; script-src " . $origin . "/html/js/; frame-ancestors 'none'; block-all-mixed-content;");
	header("Feature-Policy: accelerometer 'none'; autoplay 'none'; camera 'none'; document-domain 'none'; encrypted-media 'none'; focus-without-user-activation 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; usb 'none'; xr-spatial-tracking 'none'; sync-xhr 'none'; picture-in-picture 'none';");

	session_start();

//--------------------------------------------------
// Challenge

	if ($method == 'GET') {
		$_SESSION['challenge'] = random_bytes(32);
	}

	$challenge = ($_SESSION['challenge'] ?? '');

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
		// Checks basic

			if (($webauthn_data['type'] ?? '') !== 'public-key') {
				$errors[] = 'Returned type is not a "public-key".';
			}

			if (($client_data['type'] ?? '') !== 'webauthn.create') {
				$errors[] = 'Returned type is not "webauthn.create".';
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

				// Only use $challenge check for attestation

		//--------------------------------------------------
		// Get public key

			$key_details = ($webauthn_data['auth']['attestedCredentialData']['publicKey'] ?? '');
			$key_pem = NULL;

			if (!$key_details) {

				$errors[] = 'No public key found.';

			} else if ($key_details['algorithm'] != $algorithm) {

				$errors[] = 'Different algorithm used.';

			} else {

				$key_pem = $key_details['pem'];

			}

		//--------------------------------------------------
		// Store

			if (count($errors) == 0) {

				$_SESSION['webauthn_data_create'] = $webauthn_data; // Only for debugging.

				$_SESSION['user_key_id'] = $webauthn_data['id'];
				$_SESSION['user_key_value'] = $key_pem;

				// Ignore $webauthn_data['auth']['signCount'], it's set to 0.

				header('Location: ./check.php');
				exit('<p><a href="./check.php">Next</a></p>');

			}

		//--------------------------------------------------
		// Show errors

			header('Content-Type: text/plain; charset=UTF-8');

			echo "\n--------------------------------------------------\n\n";
			print_r(base64_encode($challenge));
			echo "\n--------------------------------------------------\n\n";
			print_r($errors);
			echo "\n--------------------------------------------------\n\n";
			print_r($webauthn_data);
			echo "\n--------------------------------------------------\n\n";
			print_r($key_pem);
			echo "\n--------------------------------------------------\n\n";
			exit();

	}

//--------------------------------------------------
// Request

	$request = [
			'publicKey' => [
					'rp' => [
							'name' => 'Test Website',
							'id' => $host,
							// 'icon' => 'https://example.com/login.png',
						],
					'user' => [
							'id' => 125,
							'name' => 'craig@example.com',
							'displayName' => 'Craig Francis',
						],
					'challenge' => base64_encode($challenge),
					'pubKeyCredParams' => [
							[
								'type' => "public-key", // As of March 2019, only "public-key" may be used.
								'alg' => $algorithm,
							],
						],
					'timeout' => 10000, // In milliseconds
					'attestation' => 'none', // Other options include "direct" and "indirect" - but these show the warning "Allow this site to see your security key?", saying this site "wants to see the make and model of your security key".
					'excludeCredentials' => [ // Avoid creating new public key credentials (e.g. existing user who has already setup WebAuthn).
							// [
							// 	'type' => "public-key",
							// 	'id' => new Uint8Array(26),
							// ],
						],
					'userVerification' => 'discouraged',
				],
		];

?>
<!DOCTYPE html>
<html lang="en-GB" xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta charset="UTF-8" />
	<title>Create</title>
	<script src="./js/webauthn.js" async="async"></script>
</head>
<body>

	<form action="<?= htmlentities($uri) ?>" method="post" accept-charset="UTF-8">

		<input type="submit" name="auth" value="Create" data-webauthn-create="<?= htmlentities(json_encode($request)) ?>" />

	</form>

</body>
</html>