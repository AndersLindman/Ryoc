/**
 * File: ryoc-cipher.js
 * Description: This file implements the Ryoc cipher, a 512-bit Feistel cipher using HMAC-SHA-256 as the round function.
 * Key Components:
 * 1. Key Schedule: Generates 8 round keys using HKDF with SHA-256 and a fixed salt.
 * 2. Padding Functions: Implements PKCS#7 padding and unpadding for block alignment.
 * 3. Feistel Network: Provides Feistel-based encryption and decryption using HMAC-SHA-256 as the round function.
 * 4. CBC Mode: Implements Cipher Block Chaining (CBC) mode for encrypting and decrypting data with a 512-bit block size.
 *
 * Dependencies:
 * - Web Crypto API: Used for cryptographic operations (e.g., HMAC, SHA-256, HKDF).
 *
 * Usage:
 * - Use `encrypt` and `decrypt` for encrypting and decrypting data in CBC mode.
 * - Ensure the key and IV are securely managed and unique for each encryption operation.
 *
 * Security Considerations:
 * - The IV must be unique for each encryption operation to prevent vulnerabilities.
 * - Ensure the key is securely generated.
 * - Ensure the key is securely stored or ephemeral.
 *
 * Author: Anders Lindman
 * Date: 2025-01-06
 * Version: 1.0
 */

// Key schedule: Generate round keys using HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
async function generateRoundKeys(masterKey, numRounds, salt) {
  const encoder = new TextEncoder() // Converts strings to Uint8Array
  const decoder = new TextDecoder() // Converts Uint8Array back to string
  const roundKeys = []
  const keyData = masterKey // Master key provided as input
  const cryptoKey = await crypto.subtle.importKey(
    "raw", // Format of the key material (raw bytes)
    keyData, // Key material (Uint8Array)
    { name: "HKDF" }, // Algorithm for key derivation (HKDF)
    false, // Not extractable (key cannot be exported)
    ["deriveKey", "deriveBits"], // Key usages (derive more keys or bits)
  )

  // Generate a round key for each round of the Feistel network
  for (let i = 0; i < numRounds; i++) {
    const derivationMaterial = encoder.encode("RoundKey" + i) // Distinct info for each round

    try {
      const roundKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256", // Use SHA-256 as the hashing algorithm
          salt: salt, // Salt value for HKDF (should be unique per encryption)
          info: derivationMaterial, // Context-specific info for each round
        },
        cryptoKey, // Base key from which to derive round keys
        { name: "HMAC", hash: "SHA-256", length: 256 }, // Derived key will be an HMAC key with SHA-256
        false, // Not extractable
        ["sign"], // Key usage (used for signing/encryption)
      )
      roundKeys.push(roundKey) // Store the derived round key
    } catch (error) {
      console.log("An error occurred while generating round keys: " + error)
    }
  }

  roundKeys.push(cryptoKey) // Add the original master key at the end for whitening purposes
  return roundKeys
}

// Padding functions: Implement PKCS#7 padding and unpadding for block alignment
function padPKCS7(data, blockSize) {
  const paddingLength = blockSize - (data.length % blockSize) // Calculate how much padding is needed
  const padding = new Uint8Array(paddingLength).fill(paddingLength) // Create padding bytes
  const paddedData = new Uint8Array(data.length + paddingLength) // Create a new array with space for padding
  paddedData.set(data) // Copy original data into the new array
  paddedData.set(padding, data.length) // Append padding bytes
  return paddedData // Return the padded data
}

function unpadPKCS7(data) {
  if (!data || data.length === 0) {
    throw new Error("Invalid data for unpadding") // Data must not be empty
  }
  const paddingLength = data[data.length - 1] // Get the padding length from the last byte
  if (paddingLength > data.length) {
    throw new Error("Invalid padding length") // Padding length must not exceed data length
  }
  return data.subarray(0, data.length - paddingLength) // Remove padding and return unpadded data
}

// Feistel network processing: Encrypt or decrypt a single block using the Feistel structure
async function feistelProcess(block, keys, isEncrypt) {
  const blockSize = 32 // 32 bytes = 256 bits (half of the 512-bit block)
  let left = Uint8Array.from(block.subarray(0, blockSize)) // Left half of the block
  let right = Uint8Array.from(block.subarray(blockSize, 2 * blockSize)) // Right half of the block

  if (!isEncrypt) {
    // For decryption, swap left and right halves initially
    const temp = left
    left = right
    right = temp
  }

  const tempArray = new Uint8Array(blockSize)

  // Perform 8 rounds of the Feistel network
  for (let i = 0; i < 8; i++) {
    tempArray.set(left) // Save the current left half
    left.set(right) // Set the new left half to the current right half
    const roundOutput = await roundFunction(right, keys[isEncrypt ? i : 7 - i]) // Apply the round function
    for (let j = 0; j < blockSize; j++) {
      right[j] = tempArray[j] ^ roundOutput[j] // XOR the saved left half with the round output
    }
  }

  // Combine the halves back into a single 512-bit block
  const result = new Uint8Array(2 * blockSize)
  if (isEncrypt) {
    result.set(left, 0) // Left half goes first for encryption
    result.set(right, blockSize) // Right half goes second
  } else {
    result.set(right, 0) // Right half goes first for decryption
    result.set(left, blockSize) // Left half goes second
  }
  return result
}

// Encrypt a single block using the Feistel network
async function feistelEncrypt(block, keys) {
  return feistelProcess(block, keys, true)
}

// Decrypt a single block using the Feistel network
async function feistelDecrypt(block, keys) {
  return feistelProcess(block, keys, false)
}

// Round function: Uses HMAC-SHA-256 as the round function in the Feistel network
async function roundFunction(data, cryptoKey) {
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, data) // Sign the data using HMAC with the given key
  return new Uint8Array(signature) // Convert the signature to a Uint8Array
}

// Derive HKDF keys: Helper function to derive whitening keys using HKDF
async function deriveHKDFKey(cryptoKey, salt, info, lengthBits) {
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt, info: info }, // HKDF parameters
      cryptoKey, // Base key for derivation
      lengthBits, // Length of the derived key in bits
    ),
  )
}

// Feistel network in CBC mode: Encrypt or decrypt data in CBC mode with whitening keys
async function feistelCBC(dataBytes, keys, iv, salt, isEncrypt) {
  const blockSize = 64 // 64 bytes = 512 bits (block size for CBC mode)
  let blocks = []

  // If encrypting, apply PKCS#7 padding to align the data to the block size
  if (isEncrypt) {
    blocks = padPKCS7(dataBytes, blockSize)
  } else {
    blocks = dataBytes // No padding needed for decryption
  }

  const processedBlocks = [] // Array to store processed blocks
  let previousBlock = iv // Initialize the previous block with the IV
  const cryptoKey = keys[8] // The last key in the array is used for whitening

  // Pre-allocate arrays for performance
  const whitenedBlock = new Uint8Array(blockSize)
  const blockToFeistel = new Uint8Array(blockSize)
  const postWhitenedBlock = new Uint8Array(blockSize)
  const unWhitenedBlock = new Uint8Array(blockSize)

  // Process each block in the data
  for (let i = 0; i < blocks.length; i += blockSize) {
    const block = blocks.subarray(i, i + blockSize)

    // Derive whitening keys using HKDF
    const preWhiteningInfo = new TextEncoder().encode(`pre-whitening-${i}`)
    const postWhiteningInfo = new TextEncoder().encode(`post-whitening-${i}`)
    const preWhiteningKeyBytes = await deriveHKDFKey(
      cryptoKey,
      salt,
      preWhiteningInfo,
      blockSize * 8, // Derive a key of 512 bits (64 bytes)
    )
    const postWhiteningKeyBytes = await deriveHKDFKey(
      cryptoKey,
      salt,
      postWhiteningInfo,
      blockSize * 8, // Derive a key of 512 bits (64 bytes)
    )

    if (isEncrypt) {
      // Pre-whitening: XOR the block with the pre-whitening key
      for (let j = 0; j < blockSize; j++) {
        whitenedBlock[j] = block[j] ^ preWhiteningKeyBytes[j]
      }

      // CBC XOR: XOR the whitened block with the previous block (or IV for the first block)
      for (let j = 0; j < blockSize; j++) {
        blockToFeistel[j] = whitenedBlock[j] ^ previousBlock[j]
      }

      // Feistel encryption: Encrypt the block using the Feistel network
      const feistelOutput = await feistelEncrypt(blockToFeistel, keys)

      // Post-whitening: XOR the Feistel output with the post-whitening key
      for (let j = 0; j < blockSize; j++) {
        postWhitenedBlock[j] = feistelOutput[j] ^ postWhiteningKeyBytes[j]
      }

      processedBlocks.push(new Uint8Array(postWhitenedBlock)) // Store the processed block
      previousBlock = postWhitenedBlock // Update the previous block for the next iteration
    } else {
      // Post-unwhitening: XOR the block with the post-whitening key
      for (let j = 0; j < blockSize; j++) {
        unWhitenedBlock[j] = block[j] ^ postWhiteningKeyBytes[j]
      }

      // Feistel decryption: Decrypt the block using the Feistel network
      const feistelOutput = await feistelDecrypt(unWhitenedBlock, keys)

      // Reverse CBC XOR and pre-unwhitening: XOR the Feistel output with the pre-whitening key and the previous block
      for (let j = 0; j < blockSize; j++) {
        blockToFeistel[j] =
          feistelOutput[j] ^ preWhiteningKeyBytes[j] ^ previousBlock[j]
      }

      processedBlocks.push(new Uint8Array(blockToFeistel)) // Store the processed block
      previousBlock = block // Update the previous block for the next iteration
    }
  }

  if (isEncrypt) {
    // Concatenate the salt, IV, and processed blocks to form the final ciphertext
    let ciphertext = new Uint8Array(
      salt.length + iv.length + processedBlocks.length * blockSize,
    )
    ciphertext.set(salt, 0) // Add the salt at the beginning
    ciphertext.set(iv, 32) // Add the IV after the salt
    let offset = salt.length + iv.length
    processedBlocks.forEach((block) => {
      ciphertext.set(block, offset) // Add each processed block
      offset += block.length
    })
    return ciphertext
  } else {
    // Concatenate the processed blocks to form the plaintext
    let paddedPlaintext = new Uint8Array(processedBlocks.length * blockSize)
    let offset = 0
    processedBlocks.forEach((block) => {
      paddedPlaintext.set(block, offset) // Add each processed block
      offset += block.length
    })

    // Remove PKCS#7 padding to get the final plaintext
    return unpadPKCS7(paddedPlaintext)
  }
}

// High-level encryption function: Encrypts plaintext using CBC mode with whitening keys
async function encryptCBC(plaintextBytes, keys, iv, salt) {
  return feistelCBC(plaintextBytes, keys, iv, salt, true)
}

// High-level decryption function: Decrypts ciphertext using CBC mode with whitening keys
async function decryptCBC(ciphertext, keys) {
  const blockSize = 64 // 64 bytes = 512 bits (block size for CBC mode)
  const salt = ciphertext.subarray(0, 32) // Extract the salt from the ciphertext
  const iv = ciphertext.subarray(32, 32 + blockSize) // Extract the IV from the ciphertext
  const encryptedData = ciphertext.subarray(blockSize + 32) // Extract the actual encrypted data

  // Check that the ciphertext length is valid
  if ((ciphertext.length - blockSize - 32) % blockSize !== 0) {
    throw new Error(
      "Ciphertext must be a multiple of 64 bytes + salt (32 bytes)",
    )
  }

  return feistelCBC(encryptedData, keys, iv, salt, false)
}

// Encryption function: Includes key schedule generation and CBC encryption
async function encrypt(plaintext, key, iv, salt) {
  const keys = await generateRoundKeys(key, 8, salt) // Generate round keys using HKDF
  return encryptCBC(plaintext, keys, iv, salt) // Encrypt the plaintext using CBC mode
}

// Decryption function: Includes key schedule generation and CBC decryption
async function decrypt(ciphertext, key) {
  const salt = ciphertext.subarray(0, 32) // Extract the salt from the ciphertext
  const keys = await generateRoundKeys(key, 8, salt) // Generate round keys using HKDF
  return decryptCBC(ciphertext, keys) // Decrypt the ciphertext using CBC mode
}

// Safe Base64 conversion: Convert binary data to Base64 and vice versa
function bufferToBase64(buffer) {
  const binString = Array.from(buffer, (byte) =>
    String.fromCodePoint(byte),
  ).join("") // Convert each byte to a character
  return btoa(binString) // Encode the string as Base64
}

function base64ToBuffer(base64) {
  const binString = atob(base64) // Decode the Base64 string
  return Uint8Array.from(binString, (m) => m.codePointAt(0)) // Convert each character back to a byte
}

// High-level convenience functions for encrypting and decrypting strings
export async function encryptString(plaintext, passphrase) {
  const iv = crypto.getRandomValues(new Uint8Array(64)) // Generate a random 512-bit IV
  const salt = crypto.getRandomValues(new Uint8Array(32)) // Generate a random 256-bit salt
  const encoder = new TextEncoder()
  const masterKey = encoder.encode(passphrase) // Convert the passphrase to a Uint8Array
  const plaintextBytes = encoder.encode(plaintext) // Convert the plaintext to a Uint8Array
  const ciphertextBytes = await encrypt(plaintextBytes, masterKey, iv, salt) // Encrypt the plaintext
  return bufferToBase64(ciphertextBytes) // Return the ciphertext as a Base64 string
}

export async function decryptString(ciphertextBase64, passphrase) {
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const masterKey = encoder.encode(passphrase) // Convert the passphrase to a Uint8Array
  const ciphertext = base64ToBuffer(ciphertextBase64) // Convert the Base64 ciphertext back to a Uint8Array
  const plaintextBytes = await decrypt(ciphertext, masterKey) // Decrypt the ciphertext
  return decoder.decode(plaintextBytes) // Convert the decrypted bytes back to a string
}

// Example usage: Demonstrates how to use the encryption and decryption functions
(async () => {
  const plaintext = "This is a secret message of arbitrary length!"
  const passphrase = "my-secret-passphrase" // Replace with a secure passphrase

  try {
    // Encryption
    const ciphertextBase64 = await encryptString(plaintext, passphrase)
    console.log("Encrypted Text:", ciphertextBase64)

    // Decryption
    const decryptedText = await decryptString(ciphertextBase64, passphrase)
    console.log("Decrypted Text:", decryptedText)
  } catch (error) {
    console.error("Error:", error)
  }
})()
