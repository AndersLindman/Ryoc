# Ryoc: A Feistel cipher with CBC Mode and HMAC-SHA-256

This project implements a **Feistel cipher** using **CBC (Cipher Block Chaining) mode** and **HMAC-SHA-256** as the round function. The cipher supports encryption and decryption of arbitrary-length plaintexts, with padding handled using **PKCS7**.
The name Ryoc stands for "Roll your own crypto" and is a play on the slogan "Don't roll your own crypto".

## Features
- **Feistel Cipher**: A symmetric encryption structure that uses a Feistel network with 8 rounds.
- **512-bit Block Size**: Enhances future-proofing for long-term data security.
- **256-bit key length**: Provides large key space for post-quantum cryptography (PCQ) security.
- **CBC Mode**: Offers better security by chaining blocks together.
- **Key Schedule**: Generates unique round keys with strong diversification using HKDF.
- **HMAC-SHA-256**: Used as the round function for secure hashing.
- **256-bit salt**: Makes the round keys unique for each ciphertext.
- **512-bit Initial Vector (IV)**: Enables unique ciphertexts and strengthens CBC mode.
- **PKCS7 Padding**: Ensures plaintexts of arbitrary lengths can be encrypted.

## Usage

### Prerequisites
- A modern browser with support for the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

### Installation
No installation is required. Simply include the JavaScript code in your project.

### Example
Here's how to use the Feistel cipher for encryption and decryption:

```javascript
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
```

## How It Works

### Feistel Cipher
The Feistel cipher splits the input block into two halves (`left` and `right`). During each round, the `right` half is processed using the round function (HMAC-SHA-256) and XORed with the `left` half. The halves are then swapped. This process is repeated for 8 rounds in Ryoc.

### CBC Mode
CBC mode XORs each plaintext block with the previous ciphertext block before encryption. For the first block, the initialization vector (IV) is used.

### PKCS7 Padding
Plaintexts that are not a multiple of the block size (64 bytes) are padded using PKCS7. During decryption, the padding is removed to recover the original plaintext.

---

## Limitations
- **Key Size**: The key is used directly for HMAC-SHA-256, so its security depends on the strength of the key.
- **Performance**: The implementation is not optimized for performance and is intended for proof-of-concept, experimental and evaluation purposes.

---

## License
This project is licensed under the Creative Commons 0 (CC0) license. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments
- The Feistel cipher structure is based on classical cryptographic principles.
- The Web Crypto API is used for secure hashing and key management.
