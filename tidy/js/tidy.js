
;(function(document, window, undefined) {

	//--------------------------------------------------
	// Checks

		'use strict';

		if (!('Uint8Array' in window) || !('credentials' in window.navigator)) {
			return;
		}

	//--------------------------------------------------
	// Conversion functions

		function uint8array_to_base64(array) { // https://stackoverflow.com/a/12713326/6632
			return window.btoa(String.fromCharCode.apply(null, array));
		}

		function buffer_to_base64(buffer) {
			return uint8array_to_base64(new Uint8Array(buffer));
		}

		function uint8array_to_hex(array) { // https://stackoverflow.com/a/40031979/6632
			return Array.prototype.map.call(array, function (x) {
					return ('00' + x.toString(16)).slice(-2);
				}).join('');
		}

		function uint8array_to_buffer(array) { // https://stackoverflow.com/a/54646864/6632
			return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
		}

		function buffer_to_hex(buffer) {
			return uint8array_to_hex(new Uint8Array(buffer));
		}

		function base64_to_uint8array(base64) { // https://stackoverflow.com/a/21797381/6632

			var binary = window.atob(base64),
				array = new Uint8Array(new ArrayBuffer(binary.length));

			for (var k = (binary.length - 1); k >= 0; k--) {
				array[k] = binary.charCodeAt(k);
			}

			return array;

		}

	//--------------------------------------------------
	// CBOR parser

			// https://github.com/paroga/cbor-js/blob/master/cbor.js
			// @author Patrick Gansterer <paroga@paroga.com>
			// @copyright 2014-2016
			// @license https://github.com/paroga/cbor-js/blob/master/LICENSE MIT

		var CBOR = (function(undefined) {

				var POW_2_24 = 5.960464477539063e-8,
						POW_2_32 = 4294967296,
						POW_2_53 = 9007199254740992;

				function encode(value) {
					var data = new ArrayBuffer(256);
					var dataView = new DataView(data);
					var lastLength;
					var offset = 0;

					function prepareWrite(length) {
						var newByteLength = data.byteLength;
						var requiredLength = offset + length;
						while (newByteLength < requiredLength)
							newByteLength <<= 1;
						if (newByteLength !== data.byteLength) {
							var oldDataView = dataView;
							data = new ArrayBuffer(newByteLength);
							dataView = new DataView(data);
							var uint32count = (offset + 3) >> 2;
							for (var i = 0; i < uint32count; ++i)
								dataView.setUint32(i << 2, oldDataView.getUint32(i << 2));
						}

						lastLength = length;
						return dataView;
					}
					function commitWrite() {
						offset += lastLength;
					}
					function writeFloat64(value) {
						commitWrite(prepareWrite(8).setFloat64(offset, value));
					}
					function writeUint8(value) {
						commitWrite(prepareWrite(1).setUint8(offset, value));
					}
					function writeUint8Array(value) {
						var dataView = prepareWrite(value.length);
						for (var i = 0; i < value.length; ++i)
							dataView.setUint8(offset + i, value[i]);
						commitWrite();
					}
					function writeUint16(value) {
						commitWrite(prepareWrite(2).setUint16(offset, value));
					}
					function writeUint32(value) {
						commitWrite(prepareWrite(4).setUint32(offset, value));
					}
					function writeUint64(value) {
						var low = value % POW_2_32;
						var high = (value - low) / POW_2_32;
						var dataView = prepareWrite(8);
						dataView.setUint32(offset, high);
						dataView.setUint32(offset + 4, low);
						commitWrite();
					}
					function writeTypeAndLength(type, length) {
						if (length < 24) {
							writeUint8(type << 5 | length);
						} else if (length < 0x100) {
							writeUint8(type << 5 | 24);
							writeUint8(length);
						} else if (length < 0x10000) {
							writeUint8(type << 5 | 25);
							writeUint16(length);
						} else if (length < 0x100000000) {
							writeUint8(type << 5 | 26);
							writeUint32(length);
						} else {
							writeUint8(type << 5 | 27);
							writeUint64(length);
						}
					}

					function encodeItem(value) {
						var i;

						if (value === false)
							return writeUint8(0xf4);
						if (value === true)
							return writeUint8(0xf5);
						if (value === null)
							return writeUint8(0xf6);
						if (value === undefined)
							return writeUint8(0xf7);

						switch (typeof value) {
							case "number":
								if (Math.floor(value) === value) {
									if (0 <= value && value <= POW_2_53)
										return writeTypeAndLength(0, value);
									if (-POW_2_53 <= value && value < 0)
										return writeTypeAndLength(1, -(value + 1));
								}
								writeUint8(0xfb);
								return writeFloat64(value);

							case "string":
								var utf8data = [];
								for (i = 0; i < value.length; ++i) {
									var charCode = value.charCodeAt(i);
									if (charCode < 0x80) {
										utf8data.push(charCode);
									} else if (charCode < 0x800) {
										utf8data.push(0xc0 | charCode >> 6);
										utf8data.push(0x80 | charCode & 0x3f);
									} else if (charCode < 0xd800) {
										utf8data.push(0xe0 | charCode >> 12);
										utf8data.push(0x80 | (charCode >> 6)	& 0x3f);
										utf8data.push(0x80 | charCode & 0x3f);
									} else {
										charCode = (charCode & 0x3ff) << 10;
										charCode |= value.charCodeAt(++i) & 0x3ff;
										charCode += 0x10000;

										utf8data.push(0xf0 | charCode >> 18);
										utf8data.push(0x80 | (charCode >> 12)	& 0x3f);
										utf8data.push(0x80 | (charCode >> 6)	& 0x3f);
										utf8data.push(0x80 | charCode & 0x3f);
									}
								}

								writeTypeAndLength(3, utf8data.length);
								return writeUint8Array(utf8data);

							default:
								var length;
								if (Array.isArray(value)) {
									length = value.length;
									writeTypeAndLength(4, length);
									for (i = 0; i < length; ++i)
										encodeItem(value[i]);
								} else if (value instanceof Uint8Array) {
									writeTypeAndLength(2, value.length);
									writeUint8Array(value);
								} else {
									var keys = Object.keys(value);
									length = keys.length;
									writeTypeAndLength(5, length);
									for (i = 0; i < length; ++i) {
										var key = keys[i];
										encodeItem(key);
										encodeItem(value[key]);
									}
								}
						}
					}

					encodeItem(value);

					if ("slice" in data)
						return data.slice(0, offset);

					var ret = new ArrayBuffer(offset);
					var retView = new DataView(ret);
					for (var i = 0; i < offset; ++i)
						retView.setUint8(i, dataView.getUint8(i));
					return ret;
				}

				function decode(data, tagger, simpleValue) {
					var dataView = new DataView(data);
					var offset = 0;

					if (typeof tagger !== "function")
						tagger = function(value) { return value; };
					if (typeof simpleValue !== "function")
						simpleValue = function() { return undefined; };

					function commitRead(length, value) {
						offset += length;
						return value;
					}
					function readArrayBuffer(length) {
						return commitRead(length, new Uint8Array(data, offset, length));
					}
					function readFloat16() {
						var tempArrayBuffer = new ArrayBuffer(4);
						var tempDataView = new DataView(tempArrayBuffer);
						var value = readUint16();

						var sign = value & 0x8000;
						var exponent = value & 0x7c00;
						var fraction = value & 0x03ff;

						if (exponent === 0x7c00)
							exponent = 0xff << 10;
						else if (exponent !== 0)
							exponent += (127 - 15) << 10;
						else if (fraction !== 0)
							return (sign ? -1 : 1) * fraction * POW_2_24;

						tempDataView.setUint32(0, sign << 16 | exponent << 13 | fraction << 13);
						return tempDataView.getFloat32(0);
					}
					function readFloat32() {
						return commitRead(4, dataView.getFloat32(offset));
					}
					function readFloat64() {
						return commitRead(8, dataView.getFloat64(offset));
					}
					function readUint8() {
						return commitRead(1, dataView.getUint8(offset));
					}
					function readUint16() {
						return commitRead(2, dataView.getUint16(offset));
					}
					function readUint32() {
						return commitRead(4, dataView.getUint32(offset));
					}
					function readUint64() {
						return readUint32() * POW_2_32 + readUint32();
					}
					function readBreak() {
						if (dataView.getUint8(offset) !== 0xff)
							return false;
						offset += 1;
						return true;
					}
					function readLength(additionalInformation) {
						if (additionalInformation < 24)
							return additionalInformation;
						if (additionalInformation === 24)
							return readUint8();
						if (additionalInformation === 25)
							return readUint16();
						if (additionalInformation === 26)
							return readUint32();
						if (additionalInformation === 27)
							return readUint64();
						if (additionalInformation === 31)
							return -1;
						throw "Invalid length encoding";
					}
					function readIndefiniteStringLength(majorType) {
						var initialByte = readUint8();
						if (initialByte === 0xff)
							return -1;
						var length = readLength(initialByte & 0x1f);
						if (length < 0 || (initialByte >> 5) !== majorType)
							throw "Invalid indefinite length element";
						return length;
					}

					function appendUtf16Data(utf16data, length) {
						for (var i = 0; i < length; ++i) {
							var value = readUint8();
							if (value & 0x80) {
								if (value < 0xe0) {
									value = (value & 0x1f) <<	6
												| (readUint8() & 0x3f);
									length -= 1;
								} else if (value < 0xf0) {
									value = (value & 0x0f) << 12
												| (readUint8() & 0x3f) << 6
												| (readUint8() & 0x3f);
									length -= 2;
								} else {
									value = (value & 0x0f) << 18
												| (readUint8() & 0x3f) << 12
												| (readUint8() & 0x3f) << 6
												| (readUint8() & 0x3f);
									length -= 3;
								}
							}

							if (value < 0x10000) {
								utf16data.push(value);
							} else {
								value -= 0x10000;
								utf16data.push(0xd800 | (value >> 10));
								utf16data.push(0xdc00 | (value & 0x3ff));
							}
						}
					}

					function decodeItem() {
						var initialByte = readUint8();
						var majorType = initialByte >> 5;
						var additionalInformation = initialByte & 0x1f;
						var i;
						var length;

						if (majorType === 7) {
							switch (additionalInformation) {
								case 25:
									return readFloat16();
								case 26:
									return readFloat32();
								case 27:
									return readFloat64();
							}
						}

						length = readLength(additionalInformation);
						if (length < 0 && (majorType < 2 || 6 < majorType))
							throw "Invalid length";

						switch (majorType) {
							case 0:
								return length;
							case 1:
								return -1 - length;
							case 2:
								if (length < 0) {
									var elements = [];
									var fullArrayLength = 0;
									while ((length = readIndefiniteStringLength(majorType)) >= 0) {
										fullArrayLength += length;
										elements.push(readArrayBuffer(length));
									}
									var fullArray = new Uint8Array(fullArrayLength);
									var fullArrayOffset = 0;
									for (i = 0; i < elements.length; ++i) {
										fullArray.set(elements[i], fullArrayOffset);
										fullArrayOffset += elements[i].length;
									}
									return fullArray;
								}
								return readArrayBuffer(length);
							case 3:
								var utf16data = [];
								if (length < 0) {
									while ((length = readIndefiniteStringLength(majorType)) >= 0)
										appendUtf16Data(utf16data, length);
								} else
									appendUtf16Data(utf16data, length);
								return String.fromCharCode.apply(null, utf16data);
							case 4:
								var retArray;
								if (length < 0) {
									retArray = [];
									while (!readBreak())
										retArray.push(decodeItem());
								} else {
									retArray = new Array(length);
									for (i = 0; i < length; ++i)
										retArray[i] = decodeItem();
								}
								return retArray;
							case 5:
								var retObject = {};
								for (i = 0; i < length || length < 0 && !readBreak(); ++i) {
									var key = decodeItem();
									retObject[key] = decodeItem();
								}
								return retObject;
							case 6:
								return tagger(decodeItem(), length);
							case 7:
								switch (length) {
									case 20:
										return false;
									case 21:
										return true;
									case 22:
										return null;
									case 23:
										return undefined;
									default:
										return simpleValue(length);
								}
						}
					}
					// var ret = decodeItem();
					// if (offset !== data.byteLength)
					// 	throw "Remaining bytes";
					// return ret;
					return {
							'data': decodeItem(),
							'length': offset,
						};
				}

				return {'encode': encode, 'decode': decode};

			})();

	//--------------------------------------------------
	// Parsing of authenticator data

		function authenticator_buffer_parse(authenticator_buffer) {

				// https://w3c.github.io/webauthn/#sctn-attestation
				// https://w3c.github.io/webauthn/#authenticator-data
				// https://w3c.github.io/webauthn/#sctn-attested-credential-data
				// https://webauthn.guide/
				// https://apowers313.github.io/fido2-lib/parser.js.html

			var dataView  = new DataView(authenticator_buffer, 0);

			var offset    = 0;
			var rpIdHash  = dataView.buffer.slice(offset, offset + 32); offset += 32;
			var flags     = dataView.getUint8(offset); offset += 1;
			var signCount = dataView.getUint32(offset, false); offset += 4; // 32-bit unsigned big-endian integer

				// console.log((flags >>> 0).toString(2).padEnd(8, '0'));

			var data = {
					'rpIdHash': buffer_to_hex(rpIdHash),
					'flags': {
							'UP':    !!(flags & 0x01), // 1   = Bit 0: User Present (UP) result.
							'RFU1':  !!(flags & 0x02), // 2   = Bit 1: Reserved for future use (RFU1).
							'UV':    !!(flags & 0x04), // 4   = Bit 2: User Verified (UV) result.
							'RFU2a': !!(flags & 0x08), // 8   = Bit 3: Reserved for future use (RFU2).
							'RFU2b': !!(flags & 0x10), // 16  = Bit 4: Reserved for future use (RFU2).
							'RFU2c': !!(flags & 0x20), // 32  = Bit 5: Reserved for future use (RFU2).
							'AT':    !!(flags & 0x40), // 64  = Bit 6: Attested credential data included (AT).
							'ED':    !!(flags & 0x80)  // 128 = Bit 7: Extension data included (ED).
						},
					'signCount': signCount,
					'attestedCredentialData': null,
					'extensions': null
				};

			if (data['flags']['AT']) {

				//--------------------------------------------------
				// Main details

					var aaguid = dataView.buffer.slice(offset, offset + 16); offset += 16;
					var credentialIdLength = dataView.getUint16(offset); offset += 2; // 53 to 55
					var credentialId = dataView.buffer.slice(offset, credentialIdLength); offset += credentialIdLength;
					var publicKeyBytes = dataView.buffer.slice(offset);
					var publicKeyObject = CBOR.decode(publicKeyBytes);

					offset += publicKeyObject['length']; // The only way to determine the 'credentialPublicKey' size is via the CBOR encoded value.

				//--------------------------------------------------
				// DER version

						// https://github.com/lbuchs/WebAuthn/blob/master/Attestation/AuthenticatorData.php
						// @author Lukas Buchs
						// @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT

					var der_prefix = new Uint8Array([ // ASN.1 DER encoding, aka X.690 ... https://en.wikipedia.org/wiki/X.690

							0x30, // DER Sequence
							0x59, // Length (2+19 + 2+66) = 89

								0x30, // DER Sequence
								0x13, // Length (2+7 + 2+8) = 19

									0x06, // DER OBJECT IDENTIFIER
									0x07, // Length
									0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID 1.2.840.10045.2.1 ecPublicKey

									0x06, // DER OBJECT IDENTIFIER
									0x08, // Length
									0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7 prime256v1

								0x03, // DER BIT STRING
								0x42, // Length (32 + 32 + 1(null) + 1) = 66
								0x00,

									0x04, // ECC uncompressed... beginning of X9.62 Key

						]);

					var der_content = new Uint8Array(der_prefix.byteLength + publicKeyObject['data'][-2].byteLength + publicKeyObject['data'][-3].byteLength);

					der_content.set(der_prefix, 0);
					der_content.set(publicKeyObject['data'][-2], der_prefix.byteLength);
					der_content.set(publicKeyObject['data'][-3], der_prefix.byteLength + publicKeyObject['data'][-2].byteLength);

					der_content = uint8array_to_base64(der_content);

					// var pem_content = der_content.match(/.{0,64}/g).join("\n").trim();
					// pem_content = '-----BEGIN PUBLIC KEY-----' + "\n" + pem_content + "\n" + '-----END PUBLIC KEY-----';

				//--------------------------------------------------
				// Store

					data['attestedCredentialData'] = {
							'aaguid': buffer_to_base64(aaguid),
							'credentialId': buffer_to_base64(credentialId),
							'publicKey': {
									'type': publicKeyObject['data'][1], // 2 = Elliptic Curve; using more magic numbers for keys and values, does this save a few bytes somewhere?
									'algorithm': publicKeyObject['data'][3], // -7 = ECDSA with SHA256
									'curve_type': publicKeyObject['data'][-1], // 1 = P-256
									'curve_x': uint8array_to_base64(publicKeyObject['data'][-2]),
									'curve_y': uint8array_to_base64(publicKeyObject['data'][-3]),
									'der': der_content
								},
						};

			}

			if (data['flags']['ED']) {

				// var extensionData = dataView.buffer.slice(offset);

			}

			return data;

		}

	//--------------------------------------------------
	// Credentials2

		window.navigator.credentials2 = {
			'create': function(options) {

					return new Promise(function(resolve, reject) {

							options['publicKey']['user']['id'] = base64_to_uint8array(options['publicKey']['user']['id']);
							options['publicKey']['challenge'] = base64_to_uint8array(options['publicKey']['challenge']);

							navigator.credentials.create(options).then(function(result) {

									//--------------------------------------------------
									// Authenticator data

										var attestation_object = CBOR.decode(result.response.attestationObject);

									//--------------------------------------------------
									// Complete

										resolve({
												'id': result.id.replace(/-/g, '+').replace(/_/g, '/'), // Use normal base64, not base64url (rfc4648)
												'type': result.type,
												'auth': authenticator_buffer_parse(uint8array_to_buffer(attestation_object['data'].authData)),
												'response': {
														'clientDataJSON': buffer_to_base64(result.response.clientDataJSON),
														'attestationObject': uint8array_to_base64(result.response.attestationObject),
													}
											});

								}).catch(function(e) {

									reject(e);

								});

					});

				},
			'get': function(options) {

					return new Promise(function(resolve, reject) {

							options['publicKey']['challenge'] = base64_to_uint8array(options['publicKey']['challenge']);

							for (var k = (options['publicKey']['allowCredentials'].length - 1); k >= 0; k--) {
								options['publicKey']['allowCredentials'][k]['id'] = base64_to_uint8array(options['publicKey']['allowCredentials'][k]['id']);
							}

							navigator.credentials.get(options).then(function(result) {

									//--------------------------------------------------
									// Complete

										resolve({
												'id': result.id.replace(/-/g, '+').replace(/_/g, '/'), // Use normal base64, not base64url (rfc4648)
												'type': result.type,
												'auth': authenticator_buffer_parse(result.response.authenticatorData),
												'response': {
														'clientDataJSON': buffer_to_base64(result.response.clientDataJSON),
														'signature': buffer_to_base64(result.response.signature),
														'authenticatorData': buffer_to_base64(result.response.authenticatorData),
													}
											});

								}).catch(function(e) {

									reject(e);

								});

					});

				},
			'store': function(credential) {
				},
			'preventSilentAccess': function() {
				}
		};

})(document, window);
