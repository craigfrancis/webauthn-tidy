<?php

	class open_ssl {

			// https://github.com/lbuchs/WebAuthn/blob/master/Attestation/AuthenticatorData.php
			// @author Lukas Buchs
			// @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT

		public static function key_pem_get($key) {

			$key = implode('', [
					"\x04", // ECC uncompressed
					base64_decode($key['curve_x']),
					base64_decode($key['curve_y']),
				]);

			$der = self::_der_sequence(
					self::_der_sequence(
						self::_der_oid("\x2A\x86\x48\xCE\x3D\x02\x01") . // OID 1.2.840.10045.2.1 ecPublicKey
						self::_der_oid("\x2A\x86\x48\xCE\x3D\x03\x01\x07")  // 1.2.840.10045.3.1.7 prime256v1
					) .
					self::_der_bitString($key)
				);

			$pem = '-----BEGIN PUBLIC KEY-----' . "\n";
			$pem .= chunk_split(base64_encode($der), 64, "\n");
			$pem .= '-----END PUBLIC KEY-----' . "\n";

			return $pem;

		}

		private static function _der_length($len) {
			if ($len < 128) {
				return chr($len);
			}
			$lenBytes = '';
			while ($len > 0) {
				$lenBytes = chr($len % 256) . $lenBytes;
				$len = intdiv($len, 256);
			}
			return chr(0x80 | strlen($lenBytes)) . $lenBytes;
		}

		private static function _der_sequence($contents) {
			return "\x30" . self::_der_length(strlen($contents)) . $contents;
		}

		private static function _der_oid($encoded) {
			return "\x06" . self::_der_length(strlen($encoded)) . $encoded;
		}

		private static function _der_bitString($bytes) {
			return "\x03" . self::_der_length(strlen($bytes) + 1) . "\x00" . $bytes;
		}

	}

?>