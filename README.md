# Snail.Toolkit.Cryptography

Symmetric AES encryption with PBKDF2 key derivation for .NET — an `ISymmetricCipher` over byte arrays and Base64 strings, configured through `IOptions` and registered with a single `AddSymmetricCipher` call.

## Features

- **Authenticated encryption**: AES-GCM, so an altered ciphertext is rejected rather than decrypted into altered plaintext
- **A fresh nonce per message**: the same text never encrypts to the same bytes twice
- **Self-describing ciphertext**: a versioned envelope carrying its own nonce and tag
- **Key derived once**: PBKDF2 runs when the cipher is built, not on every call
- **Settings checked at startup**: a bad key length or a missing passphrase stops the host, not the first request

## Installation

```bash
dotnet add package Snail.Toolkit.Cryptography
```

## Configuration

### From appsettings.json

```json
{
  "Cryptography": {
    "Passphrase": "from a secret store, not from this file",
    "Salt": "a long random value, unique per deployment",
    "Iterations": 600000,
    "DesiredKeyLength": 32,
    "HashMethod": "SHA512"
  }
}
```

```csharp
builder.Services.AddSymmetricCipher(builder.Configuration);
```

The section defaults to `Cryptography` and can be named explicitly:

```csharp
builder.Services.AddSymmetricCipher(builder.Configuration, "Encryption");
```

### In code

```csharp
builder.Services.AddSymmetricCipher(options =>
{
    options.Passphrase = secrets["Cryptography:Passphrase"];
    options.Salt = secrets["Cryptography:Salt"];
    options.Iterations = 600_000;
    options.DesiredKeyLength = 32;
    options.HashMethod = HashAlgo.SHA512;
});
```

`Passphrase` and `Salt` are required. `DesiredKeyLength` must be 16, 24 or 32, `Iterations` at least 100 000. Anything else fails validation when the host starts.

## Usage

```csharp
public class Vault(ISymmetricCipher cipher)
{
    public string Store(string data) => cipher.EncryptToBase64(data);

    public string Read(string stored) => cipher.DecryptFromBase64(stored);
}
```

```csharp
var text = cipher.EncryptToBase64("Sensitive data");
var back = cipher.DecryptFromBase64(text);

var bytes = cipher.Encrypt([1, 2, 3, 4, 5]);
var raw = cipher.Decrypt(bytes);
```

The operations are synchronous: they are CPU work over memory, and the one cost that genuinely blocked a thread — key derivation — is now paid once, when the cipher is constructed.

Each thread keeps one AES-GCM instance of its own for as long as the cipher lives. `SymmetricCipher` is disposable: the container disposes the one it registered, and that wipes every instance's copy of the key. A cipher built by hand is disposed by whoever built it.

## Ciphertext format

```
version(1) | nonce(12) | tag(16) | ciphertext(n)
```

29 bytes of overhead per value, independent of length. The version byte is what makes a future format distinguishable from this one.

`Decrypt` throws `CryptographicException` when the envelope is truncated, carries an unknown version, was altered, or was produced under a different key.

## Security

- Keep `Passphrase` in a secret store. A configuration file is not one.
- `Salt` is required and should be long and random. It is what stops a derived key from being precomputable across every deployment sharing a passphrase.
- `Iterations` defaults to 600 000, the OWASP figure for PBKDF2-HMAC-SHA512. Lowering it below 100 000 is refused.
- Passphrase and salt are read as UTF-8, so any alphabet survives them.
- There is no default passphrase and no parameterless registration. Encryption that silently works without configuration is worse than encryption that refuses to start.

## Supported hash algorithms

`SHA256`, `SHA384`, `SHA512` — used to stretch the passphrase during key derivation.

SHA-1 was removed: it was the only choice here that weakened the derived key, and leaving it selectable meant a configuration file could quietly pick it.

## Upgrading from 1.x

Version 2 changes both the ciphertext format and the API. **Data encrypted by 1.x cannot be read by 2.x** and has to be re-encrypted.

| 1.x | 2.x |
| --- | --- |
| `EncryptAsync` / `DecryptAsync` | `Encrypt` / `Decrypt` |
| `EncryptToBase64Async` / `DecryptFromBase64Async` | `EncryptToBase64` / `DecryptFromBase64` |
| `SymCryptoOpts` | `CipherOptions` |
| `IV` setting | removed — a nonce is generated per message |
| `Salt` optional | required |
| `AddSymmetricCipher()` | removed — configure it |
| `HashAlgo.SHA1` | removed |

## License

Snail.Toolkit.Cryptography is a free and open source project, released under the permissible [MIT license](LICENSE).
