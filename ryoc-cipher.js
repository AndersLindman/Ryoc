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

// Key schedule
async function generateRoundKeys(masterKey, numRounds, iv) {
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const roundKeys = []
  const salt = new Uint8Array([
    229, 60, 238, 99, 160, 218, 188, 221, 246, 45, 192, 156, 103, 54, 216, 97,
  ]) // Fixed salt
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", iv)
  const contextId = decoder.decode(hashBuffer)

  for (let i = 0; i < numRounds; i++) {
    const derivationMaterial = encoder.encode("RoundKey" + i + contextId) // Distinct info for each round
    const keyData = encoder.encode(masterKey)
    const cryptoKey = await crypto.subtle.importKey(
      "raw", // Format
      keyData, // Key material (Uint8Array)
      { name: "HKDF" }, // Algorithm for key derivation
      false, // Not extractable
      ["deriveKey"], // Key usages
    )
    cryptoKey
    try {
      const roundKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt,
          info: derivationMaterial, // Context-specific info for each round
        },
        cryptoKey, // Your master CryptoKey
        { name: "HMAC", hash: "SHA-256", length: 256 }, // Key usage and length
        false, // Not extractable
        ["sign"], // Key usages
      )
      roundKeys.push(roundKey)
    } catch (error) {
      console.log("An error: " + error)
    }
  }
  return roundKeys
}

// Padding functions
function padPKCS7(data, blockSize) {
  const paddingLength = blockSize - (data.length % blockSize)
  const padding = new Uint8Array(paddingLength).fill(paddingLength)
  const paddedData = new Uint8Array(data.length + paddingLength)
  paddedData.set(data)
  paddedData.set(padding, data.length)
  return paddedData
}

function unpadPKCS7(data) {
  if (!data || data.length === 0) {
    throw new Error("Invalid data for unpadding")
  }
  const paddingLength = data[data.length - 1]
  if (paddingLength > data.length) {
    throw new Error("Invalid padding length")
  }
  return data.slice(0, data.length - paddingLength)
}

// Feistel encryption function
async function feistelEncrypt(block, keys) {
  const encoder = new TextEncoder()
  // Split the block into two 256-bit halves
  const blockSize = 32 // 32 bytes = 256 bits
  //  const left = new Uint8Array(block.buffer, 0, blockSize); // First 32 bytes
  //  const right = new Uint8Array(block.buffer, blockSize, blockSize); // Next 32 bytes
  const left = Uint8Array.from(block.slice(0, blockSize))
  const right = Uint8Array.from(block.slice(blockSize, 2 * blockSize))

  for (let i = 0; i < 8; i++) {
    const temp = new Uint8Array(left)
    left.set(right)
    const roundOutput = await roundFunction(right, keys[i])
    for (let j = 0; j < blockSize; j++) {
      right[j] = temp[j] ^ roundOutput[j]
    }
  }

  // Combine the halves back into a single 512-bit block
  const encrypted = new Uint8Array(2 * blockSize)
  encrypted.set(left, 0)
  encrypted.set(right, blockSize)

  return encrypted
}

// Feistel decryption function
async function feistelDecrypt(block, keys) {
  const encoder = new TextEncoder()
  // Ensure the block is exactly 64 bytes
  if (block.length !== 64) {
    throw new Error("Block must be exactly 64 bytes (512 bits)")
  }

  // Split the block into two 256-bit halves
  const blockSize = 32 // 32 bytes = 256 bits
  const left = Uint8Array.from(block.slice(0, blockSize))
  const right = Uint8Array.from(block.slice(blockSize, 2 * blockSize))

  // Decryption is the same as encryption but in reverse order
  for (let i = 0; i < 8; i++) {
    const temp = new Uint8Array(right)
    right.set(left)
    const roundOutput = await roundFunction(left, keys[7 - i])
    for (let j = 0; j < blockSize; j++) {
      left[j] = temp[j] ^ roundOutput[j]
    }
  }

  // Combine the halves back into a single 512-bit block
  const decrypted = new Uint8Array(2 * blockSize)
  decrypted.set(left, 0)
  decrypted.set(right, blockSize)

  return decrypted
}

// Round function using HMAC-SHA-256
async function roundFunction(data, cryptoKey) {
  //console.log("roundFucntionCryptoKey= ", cryptoKey.algorithm)
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, data)
  return new Uint8Array(signature)
}

// Encryption with CBC mode
async function encryptCBC(plaintext, keys) {
  const blockSize = 64
  const encoder = new TextEncoder()
  const plaintextBytes = encoder.encode(plaintext)
  const paddedPlaintext = padPKCS7(plaintextBytes, blockSize)

  const encryptedBlocks = []
  const iv = crypto.getRandomValues(new Uint8Array(blockSize))
  let previousBlock = Uint8Array.from(iv) // Create a COPY of the IV

  for (let i = 0; i < paddedPlaintext.length; i += blockSize) {
    const block = paddedPlaintext.slice(i, i + blockSize)
    const blockToEncrypt = new Uint8Array(blockSize)

    for (let j = 0; j < blockSize; j++) {
      blockToEncrypt[j] = block[j] ^ previousBlock[j]
    }

    const encryptedBlock = await feistelEncrypt(blockToEncrypt, keys)
    encryptedBlocks.push(encryptedBlock)
    previousBlock = encryptedBlock // Correct: previousBlock is the *current* ciphertext block
  }
  let ciphertext = new Uint8Array(
    iv.length + encryptedBlocks.length * blockSize,
  ) // Include IV in ciphertext
  ciphertext.set(iv, 0)
  let offset = iv.length
  encryptedBlocks.forEach((block) => {
    ciphertext.set(block, offset)
    offset += block.length
  })

  return ciphertext
}

// Decryption with CBC mode (Correct)
async function decryptCBC(ciphertext, keys) {
  const blockSize = 64
  const decryptedBlocks = []
  const iv = ciphertext.slice(0, blockSize)
  let previousBlock = Uint8Array.from(iv) // Create a COPY of the IV
  const encryptedData = ciphertext.slice(blockSize)

  if ((ciphertext.length - blockSize) % blockSize !== 0) {
    throw new Error(
      "Ciphertext must be a multiple of 64 bytes + IV (512 bits + IV)",
    )
  }

  for (let i = 0; i < encryptedData.length; i += blockSize) {
    const block = Uint8Array.from(encryptedData.slice(i, i + blockSize))
    const decryptedBlock = await feistelDecrypt(block, keys)
    const plaintextBlock = new Uint8Array(blockSize)

    for (let j = 0; j < blockSize; j++) {
      plaintextBlock[j] = decryptedBlock[j] ^ previousBlock[j]
    }

    decryptedBlocks.push(plaintextBlock)
    previousBlock = block
  }

  let paddedPlaintext = new Uint8Array(decryptedBlocks.length * blockSize)
  let offset = 0
  decryptedBlocks.forEach((block) => {
    paddedPlaintext.set(block, offset)
    offset += block.length
  })

  return unpadPKCS7(paddedPlaintext)
}

// Encryption including key schedule generation.
async function encrypt(plaintext, key, iv) {
  const keys = await generateRoundKeys(key, 8, iv)
  return encryptCBC(plaintext, keys, iv)
}

// Dncryption including key schedule generation.
async function decrypt(ciphertext, key, iv) {
  const keys = await generateRoundKeys(key, 8, iv)
  return decryptCBC(ciphertext, keys, iv)
}

// Example usage
;(async () => {
  const plaintext = "This is a secret message of arbitrary length!"
  const key = "mysecretkey"
  const iv = crypto.getRandomValues(new Uint8Array(64)) // 64-byte IV

  try {
    // Encryption
    const ciphertext = await encrypt(plaintext, key, iv)
    console.log(
      "Ciphertext:",
      Array.from(ciphertext)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(""),
    )
    // Decryption
    const decryptedText = await decrypt(ciphertext, key, iv)
    const decoder = new TextDecoder()
    console.log("Decrypted Text:", decoder.decode(decryptedText))
  } catch (error) {
    console.error("Error:", error)
  }
})()
