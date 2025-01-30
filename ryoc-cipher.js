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
async function generateRoundKeys(masterKey, numRounds, salt) {
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const roundKeys = []
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", salt)
  const contextId = decoder.decode(hashBuffer)
  const keyData = masterKey

  const cryptoKey = await crypto.subtle.importKey(
    "raw", // Format
    keyData, // Key material (Uint8Array)
    { name: "HKDF" }, // Algorithm for key derivation
    false, // Not extractable
    ["deriveKey"], // Key usages
  )

  for (let i = 0; i < numRounds; i++) {
    const derivationMaterial = encoder.encode("RoundKey" + i + contextId) // Distinct info for each round
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

async function feistelProcess(block, keys, isEncrypt) {
  // Split the block into two 256-bit halves
  const blockSize = 32 // 32 bytes = 256 bits
  let left = Uint8Array.from(block.slice(0, blockSize))
  let right = Uint8Array.from(block.slice(blockSize, 2 * blockSize))
  if (!isEncrypt) {
    const temp = left
    left = right
    right = temp
  }

  for (let i = 0; i < 8; i++) {
    const temp = new Uint8Array(left)
    left.set(right)
    const roundOutput = await roundFunction(right, keys[isEncrypt ? i : 7 - i])
    for (let j = 0; j < blockSize; j++) {
      right[j] = temp[j] ^ roundOutput[j]
    }
  }

  // Combine the halves back into a single 512-bit block
  const result = new Uint8Array(2 * blockSize)
  if (isEncrypt) {
    result.set(left, 0)
    result.set(right, blockSize)
  } else {
    result.set(right, 0)
    result.set(left, blockSize)
  }

  return result
}

async function feistelEncrypt(block, keys) {
  return feistelProcess(block, keys, true)
}

async function feistelDecrypt(block, keys) {
  return feistelProcess(block, keys, false)
}

// Round function using HMAC-SHA-256
async function roundFunction(data, cryptoKey) {
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, data)
  return new Uint8Array(signature)
}

// Encryption with CBC mode
async function encryptCBC(plaintextBytes, keys, iv, salt) {
  const blockSize = 64
  const paddedPlaintext = padPKCS7(plaintextBytes, blockSize)

  const encryptedBlocks = []
  let previousBlock = iv

  for (let i = 0; i < paddedPlaintext.length; i += blockSize) {
    const block = paddedPlaintext.slice(i, i + blockSize)
    const blockToEncrypt = new Uint8Array(blockSize)

    for (let j = 0; j < blockSize; j++) {
      blockToEncrypt[j] = block[j] ^ previousBlock[j]
    }

    const encryptedBlock = await feistelEncrypt(blockToEncrypt, keys)
    encryptedBlocks.push(encryptedBlock)
    previousBlock = encryptedBlock
  }
  let ciphertext = new Uint8Array(
    salt.length + iv.length + encryptedBlocks.length * blockSize,
  ) // Include IV in ciphertext
  ciphertext.set(salt, 0)
  ciphertext.set(iv, 32)
  let offset = salt.length + iv.length
  encryptedBlocks.forEach((block) => {
    ciphertext.set(block, offset)
    offset += block.length
  })

  return ciphertext
}

// Decryption with CBC mode
async function decryptCBC(ciphertext, keys) {
  const blockSize = 64
  const decryptedBlocks = []
  const salt = ciphertext.slice(0, 32)
  const iv = ciphertext.slice(32, 32 + blockSize)
  let previousBlock = iv
  const encryptedData = ciphertext.slice(blockSize + 32)

  if ((ciphertext.length - blockSize - 32) % blockSize !== 0) {
    throw new Error(
      "Ciphertext must be a multiple of 64 bytes + salt (32 bytes)",
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
async function encrypt(plaintext, key, iv, salt) {
  const keys = await generateRoundKeys(key, 8, salt)
  return encryptCBC(plaintext, keys, iv, salt)
}

// Decryption including key schedule generation.
async function decrypt(ciphertext, key) {
  const salt = ciphertext.slice(0, 32)
  const keys = await generateRoundKeys(key, 8, salt)
  return decryptCBC(ciphertext, keys)
}

// Safe Base64 conversion
function bufferToBase64(buffer) {
  const binString = Array.from(buffer, (byte) =>
    String.fromCodePoint(byte),
  ).join("")
  return btoa(binString)
}

function base64ToBuffer(base64) {
  const binString = atob(base64)
  return Uint8Array.from(binString, (m) => m.codePointAt(0))
}

// High-level convenience functions
export async function encryptString(plaintext, passphrase) {
  const iv = crypto.getRandomValues(new Uint8Array(64)) // 512-bit IV
  const salt = crypto.getRandomValues(new Uint8Array(32)) // 256-bit random salt
  const encoder = new TextEncoder()
  const masterKey = encoder.encode(passphrase)
  const plaintextBytes = encoder.encode(plaintext)
  const ciphertextBytes = await encrypt(plaintextBytes, masterKey, iv, salt)
  return bufferToBase64(ciphertextBytes)
}

export async function decryptString(ciphertextBase64, passphrase) {
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const masterKey = encoder.encode(passphrase)
  const ciphertext = base64ToBuffer(ciphertextBase64)
  const plaintextBytes = await decrypt(ciphertext, masterKey)
  return decoder.decode(plaintextBytes)
}

// Example usage
(async () => {
  const plaintext = "This is a secret message of arbitrary length!"
  const passphrase = "my-secret-passphrase" // Replace with secure passphrase

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
