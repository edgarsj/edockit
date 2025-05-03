/**
 * Fixes ASN.1 DER encoding of RSA keys to be compatible with browser Web Crypto
 *
 * This specifically targets the issue with modulus padding in SPKI format RSA keys.
 * In DER encoding, when the high bit of an INTEGER is set, a 0x00 byte must be
 * prepended to distinguish it from a negative number. Some libraries omit this padding,
 * which works in Node.js but causes browsers to reject the key.
 */

/**
 * Fixes ASN.1 DER encoding of RSA modulus to ensure proper padding
 *
 * @param publicKeyData The original public key data as ArrayBuffer
 * @returns Fixed key with proper modulus padding
 */
export function fixRSAModulusPadding(publicKeyData: ArrayBuffer): ArrayBuffer {
  // Only log when debugging is enabled
  const debug = false;
  const log = debug ? console.log : () => {};

  const keyBytes = new Uint8Array(publicKeyData);

  // Check if we have a valid SPKI format RSA key
  // It should start with SEQUENCE tag (0x30)
  if (keyBytes[0] !== 0x30) {
    log("Not a valid SPKI format (doesn't start with SEQUENCE tag)");
    return publicKeyData;
  }

  // Look for RSA OID to confirm it's an RSA key
  const RSA_OID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
  let oidPosition = -1;

  for (let i = 0; i <= keyBytes.length - RSA_OID.length; i++) {
    let match = true;
    for (let j = 0; j < RSA_OID.length; j++) {
      if (keyBytes[i + j] !== RSA_OID[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      oidPosition = i;
      break;
    }
  }

  if (oidPosition === -1) {
    log("RSA OID not found, not an RSA key");
    return publicKeyData;
  }

  // Find the BitString that contains the key
  let bitStringPosition = -1;
  for (let i = oidPosition + RSA_OID.length; i < keyBytes.length; i++) {
    if (keyBytes[i] === 0x03) {
      // BIT STRING tag
      bitStringPosition = i;
      break;
    }
  }

  if (bitStringPosition === -1) {
    log("BIT STRING not found");
    return publicKeyData;
  }

  // Skip BIT STRING tag and length bytes to find unused bits byte
  let bitStringLengthBytes = 0;
  if ((keyBytes[bitStringPosition + 1] & 0x80) === 0) {
    // Short form length
    bitStringLengthBytes = 1;
  } else {
    // Long form length
    bitStringLengthBytes = 1 + (keyBytes[bitStringPosition + 1] & 0x7f);
  }

  // The unused bits byte follows the length bytes
  const unusedBitsPosition = bitStringPosition + 1 + bitStringLengthBytes;
  if (unusedBitsPosition >= keyBytes.length) {
    log("Invalid BIT STRING structure");
    return publicKeyData;
  }

  // The inner SEQUENCE (RSA key) should follow the unused bits byte
  const innerSequencePosition = unusedBitsPosition + 1;
  if (innerSequencePosition >= keyBytes.length || keyBytes[innerSequencePosition] !== 0x30) {
    log("Inner SEQUENCE not found or invalid");
    return publicKeyData;
  }

  // Skip the inner SEQUENCE tag and length bytes to find the modulus
  let innerSequenceLengthBytes = 0;
  if ((keyBytes[innerSequencePosition + 1] & 0x80) === 0) {
    // Short form length
    innerSequenceLengthBytes = 1;
  } else {
    // Long form length
    innerSequenceLengthBytes = 1 + (keyBytes[innerSequencePosition + 1] & 0x7f);
  }

  // The modulus should be an INTEGER (tag 0x02) after the inner SEQUENCE
  const modulusPosition = innerSequencePosition + 1 + innerSequenceLengthBytes;
  if (modulusPosition >= keyBytes.length || keyBytes[modulusPosition] !== 0x02) {
    log("Modulus INTEGER not found or invalid");
    return publicKeyData;
  }

  // Skip the INTEGER tag and parse its length to find the modulus value
  let modulusLengthBytes = 0;
  let modulusLength = 0;

  if ((keyBytes[modulusPosition + 1] & 0x80) === 0) {
    // Short form length
    modulusLength = keyBytes[modulusPosition + 1];
    modulusLengthBytes = 1;
  } else {
    // Long form length
    const numLengthBytes = keyBytes[modulusPosition + 1] & 0x7f;
    modulusLengthBytes = 1 + numLengthBytes;

    // Calculate multi-byte length
    modulusLength = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      modulusLength = (modulusLength << 8) | keyBytes[modulusPosition + 2 + i];
    }
  }

  // The first byte of the modulus value
  const modulusValuePosition = modulusPosition + 1 + modulusLengthBytes;
  if (modulusValuePosition >= keyBytes.length) {
    log("Modulus value position out of bounds");
    return publicKeyData;
  }

  // Check if the high bit is set and padding is needed
  if ((keyBytes[modulusValuePosition] & 0x80) !== 0) {
    log("High bit is set, modulus needs padding");

    // Create a new key buffer with room for the padding byte
    const fixedKey = new Uint8Array(keyBytes.length + 1);

    // Copy bytes up to the modulus value
    fixedKey.set(keyBytes.slice(0, modulusValuePosition));

    // Add the padding byte
    fixedKey[modulusValuePosition] = 0x00;

    // Copy the rest of the original key after the padding
    fixedKey.set(keyBytes.slice(modulusValuePosition), modulusValuePosition + 1);

    // Now fix all the length fields that need to be incremented

    // 1. Fix modulus length field
    if ((keyBytes[modulusPosition + 1] & 0x80) === 0) {
      // Short form
      fixedKey[modulusPosition + 1] = keyBytes[modulusPosition + 1] + 1;
    } else {
      // Long form
      const numLengthBytes = keyBytes[modulusPosition + 1] & 0x7f;
      let lengthValue = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        lengthValue = (lengthValue << 8) | keyBytes[modulusPosition + 2 + i];
      }
      lengthValue += 1;

      for (let i = numLengthBytes - 1; i >= 0; i--) {
        fixedKey[modulusPosition + 2 + i] = lengthValue & 0xff;
        lengthValue >>= 8;
      }
    }

    // 2. Fix inner SEQUENCE length field
    if ((keyBytes[innerSequencePosition + 1] & 0x80) === 0) {
      // Short form
      fixedKey[innerSequencePosition + 1] = keyBytes[innerSequencePosition + 1] + 1;
    } else {
      // Long form
      const numLengthBytes = keyBytes[innerSequencePosition + 1] & 0x7f;
      let lengthValue = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        lengthValue = (lengthValue << 8) | keyBytes[innerSequencePosition + 2 + i];
      }
      lengthValue += 1;

      for (let i = numLengthBytes - 1; i >= 0; i--) {
        fixedKey[innerSequencePosition + 2 + i] = lengthValue & 0xff;
        lengthValue >>= 8;
      }
    }

    // 3. Fix BIT STRING length field
    if ((keyBytes[bitStringPosition + 1] & 0x80) === 0) {
      // Short form
      fixedKey[bitStringPosition + 1] = keyBytes[bitStringPosition + 1] + 1;
    } else {
      // Long form
      const numLengthBytes = keyBytes[bitStringPosition + 1] & 0x7f;
      let lengthValue = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        lengthValue = (lengthValue << 8) | keyBytes[bitStringPosition + 2 + i];
      }
      lengthValue += 1;

      for (let i = numLengthBytes - 1; i >= 0; i--) {
        fixedKey[bitStringPosition + 2 + i] = lengthValue & 0xff;
        lengthValue >>= 8;
      }
    }

    // 4. Fix outer SEQUENCE length field
    if ((keyBytes[1] & 0x80) === 0) {
      // Short form
      fixedKey[1] = keyBytes[1] + 1;
    } else {
      // Long form
      const numLengthBytes = keyBytes[1] & 0x7f;
      let lengthValue = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        lengthValue = (lengthValue << 8) | keyBytes[1 + 1 + i];
      }
      lengthValue += 1;

      for (let i = numLengthBytes - 1; i >= 0; i--) {
        fixedKey[1 + 1 + i] = lengthValue & 0xff;
        lengthValue >>= 8;
      }
    }

    log("Fixed key length: " + fixedKey.length);
    return fixedKey.buffer;
  }

  // High bit isn't set, no padding needed
  log("High bit not set, no padding needed");
  return publicKeyData;
}
