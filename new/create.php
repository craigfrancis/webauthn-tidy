<?php

//--------------------------------------------------
// Config

	$host = preg_replace('/[^a-z0-9\.]/', '', ($_SERVER['HTTP_HOST'] ?? ''));
	$uri = ($_SERVER['REQUEST_URI'] ?? '');
	$origin = 'https://' . $host;
	$algorithm = -7; // Elliptic curve algorithm ECDSA with SHA-256, https://www.iana.org/assignments/cose/cose.xhtml#algorithms

	$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

	header("Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action " . $origin . $uri . "; img-src " . $origin . "; script-src " . $origin . "/new/js/; frame-ancestors 'none'; block-all-mixed-content;");
	header("Feature-Policy: accelerometer 'none'; autoplay 'none'; camera 'none'; ch-dpr 'none'; ch-device-memory 'none'; ch-downlink 'none'; ch-ect 'none'; ch-lang 'none'; ch-rtt 'none'; ch-ua 'none'; ch-ua-arch 'none'; ch-ua-platform 'none'; ch-ua-model 'none'; ch-ua-mobile 'none'; ch-ua-full-version 'none'; ch-ua-platform-version 'none'; ch-viewport-width 'none'; ch-width 'none'; clipboard-read 'none'; clipboard-write 'none'; cross-origin-isolated 'self'; document-domain 'none'; encrypted-media 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; publickey-credentials-get 'self'; screen-wake-lock 'none'; usb 'none'; xr-spatial-tracking 'none'; sync-xhr 'none'; picture-in-picture 'none';");

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

			$client_data_json = base64_decode($webauthn_data['response']['clientDataJSON'] ?? '');

			$client_data = json_decode($client_data_json, true);

		//--------------------------------------------------
		// Auth data

			$auth_data = base64_decode($webauthn_data['response']['authenticatorData']);

			$auth_data_relying_party_id = substr($auth_data, 0, 32); // rpIdHash
			$auth_data_flags            = substr($auth_data, 32, 1);
			$auth_data_sign_count       = substr($auth_data, 33, 4);
			$auth_data_sign_count       = intval(implode('', unpack('N*', $auth_data_sign_count))); // 32-bit unsigned big-endian integer

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

			if (strlen($auth_data_relying_party_id) != 32 || !hash_equals(hash('sha256', $host), bin2hex($auth_data_relying_party_id))) {
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

			$key_der = ($webauthn_data['response']['publicKey'] ?? NULL);
			if (!$key_der) {
				$errors[] = 'No public key found.';
			}

			if (($webauthn_data['response']['publicKeyAlg'] ?? NULL) !== $algorithm) {
				$errors[] = 'Different algorithm used.';
			}

		//--------------------------------------------------
		// Store

			if (count($errors) == 0) {

				$_SESSION['webauthn_data_create'] = $webauthn_data; // Only for debugging.

				$_SESSION['user_key_id'] = $webauthn_data['id'];
				$_SESSION['user_key_value'] = $key_der;

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
			print_r($key_der);
			echo "\n--------------------------------------------------\n\n";
			echo 'Sign Count: ' . $auth_data_sign_count . "\n"; // Should be 0, but can be anything.
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
	<script src="./js/create.js" async="async"></script>
	<script src="./js/polyfill.js" async="async"></script>
</head>
<body>

	<p>As of 20th July 2020, this is only supported in Chrome Canary 86.</p>

	<form action="<?= htmlentities($uri) ?>" method="post" accept-charset="UTF-8">

		<input type="submit" name="auth" value="Create" data-webauthn-create="<?= htmlentities(json_encode($request)) ?>" />

	</form>

</body>
</html>