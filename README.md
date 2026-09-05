# Snail.Toolkit.Cryptography

A robust extension for `System.Security.Cryptography` providing simplified symmetric encryption using AES with PBKDF2 key derivation.

## Features

- **AES Encryption**: 128/192/256-bit symmetric encryption
- **PBKDF2 Key Derivation**: Secure password-based key generation
- **Async API**: All operations are asynchronous
- **Multiple Input Formats**: Support for raw bytes and Base64 strings
- **Configurable Security**: Customizable iterations, hash algorithms, and key lengths

## Installation

```bash
dotnet add package Snail.Toolkit.Cryptography
```

## Configuration

### Basic Setup

```csharp
builder.Services.AddSymmetricCipher(o =>
{
    o.Passphrase = "YourSecurePassphrase123!"; // Minimum 12 characters
    o.IV = "Random16ByteValue=="; // Should be cryptographically random
    o.Iterations = 600_000; // Recommended ≥100,000 for production
    o.HashMethod = HashAlgo.SHA512;
    o.DesiredKeyLength = 32; // 256-bit AES
});
```

### Configuration from appsettings.json

```json
{
  "Cryptography": {
    "Passphrase": "YourSecurePassphrase123!",
    "IV": "Random16ByteValue==",
    "Salt": "Random16ByteSalt==",
    "Iterations": 600000,
    "DesiredKeyLength": 32,
    "HashMethod": "SHA512"
  }
}
```

```csharp
builder.Services.AddSymmetricCipher(builder.Configuration);
```

### Default Values (Development Only)

```csharp
builder.Services.AddSymmetricCipher(); // INSECURE for production!
```

## Usage

### Dependency Injection

```csharp
public class MyService(ISymmetricCipher crypto)
{
    public async Task<string> SecureOperation(string data)
    {
        var encrypted = await crypto.EncryptToBase64Async(data);
        // ... store encrypted data
        return await crypto.DecryptFromBase64Async(encrypted);
    }
}
```

### Basic Operations

```csharp
// Encryption
var ciphertext = await _crypto.EncryptToBase64Async("Sensitive data");
var rawCipher = await _crypto.EncryptAsync(new byte[] { 1, 2, 3, 4, 5 });

// Decryption
var plaintext = await _crypto.DecryptFromBase64Async(ciphertext);
var rawBytes = await _crypto.DecryptAsync(rawCipher);
```

## Security Recommendations

1. **Passphrase**:
    - Use 12+ characters with mixed cases, numbers, and symbols
    - Store in secure secret manager (not in code/config files)

2. **Initialization Vector (IV)**:
    - Should be 16 random bytes (128 bits)
    - Never reuse with same key
    - Store with ciphertext (doesn't need to be secret)

3. **Key Derivation**:
    - Use ≥100,000 iterations for PBKDF2
    - Prefer SHA-384 or SHA-512 as hash algorithm
    - Always use random salt (16+ bytes recommended)

4. **Key Length**:
    - Use 32 bytes (256-bit) for maximum AES security

## Supported Algorithms

### Hash Algorithms
- ✅ SHA-256 (minimum recommended)
- ✅ SHA-384 (balanced security/performance)
- ✅ SHA-512 (maximum security)
- ⚠️ SHA-1 (deprecated - legacy support only)

### Unsupported Algorithms
- ❌ MD5 (cryptographically broken)
- ❌ SHA-3 variants (future implementation)

## Security Considerations

⚠️ **Important**: The default configuration is INSECURE and should only be used for development/testing. Always provide proper configuration in production environments.

## License

Snail.Toolkit.Cryptography is a free and open source project, released under the permissible [MIT license](LICENSE).