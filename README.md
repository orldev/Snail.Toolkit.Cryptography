# Snail.Toolkit.Cryptography

Authenticated symmetric encryption (AES-GCM) with PBKDF2 key derivation for .NET — an `ISymmetricCipher` over byte arrays, Base64 strings and the caller's own buffers, configured through `IOptions` and registered with a single `AddSymmetricCipher` call.

## Features

- **Authenticated encryption**: AES-GCM, so an altered ciphertext is rejected rather than decrypted into altered plaintext
- **A fresh nonce per message**: the same text never encrypts to the same bytes twice
- **Self-describing ciphertext**: a versioned envelope carrying its own nonce and tag
- **Key derived once**: PBKDF2 runs when the cipher is built, not on every call
- **Settings checked at startup**: a bad key length or a missing passphrase stops the host, not the first request; a cipher built by hand is judged by the same rules in its constructor
- **Nothing allocated when you bring the buffer**: `TryEncrypt` and `TryDecrypt` seal and open in memory you own

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

`Passphrase` and `Salt` are required. `DesiredKeyLength` must be 16, 24 or 32, `Iterations` at least 100 000. Anything else fails validation when the host starts, with the setting named under the section it was read from.

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

A few AES-GCM instances wait idle and are lent to whichever thread seals or opens, one call at a time. `SymmetricCipher` is disposable: the container disposes the one it registered, which disposes the idle instances and wipes the derived key. A cipher built by hand is disposed by whoever built it, and is judged by the same rules as a registered one: a bad setting fails its constructor, naming the setting.

When the envelope should land in memory you already own, `SymmetricCipher` seals and opens without allocating:

```csharp
var envelope = new byte[SymmetricCipher.EnvelopeLength(plainText.Length)];
cipher.TryEncrypt(plainText, envelope, out _);

var opened = new byte[envelope.Length - 29];
cipher.TryDecrypt(envelope, opened, out int written);
```

Both answer `false`, with the length needed in `written`, when the buffer is too short. A bad envelope throws, as `Decrypt` does: a forgery is never reported as a sizing mistake.

## Ciphertext format

```
version(1) | nonce(12) | tag(16) | ciphertext(n)
```

29 bytes of overhead per value, independent of length. The version byte is what makes a future format distinguishable from this one.

`Decrypt` throws `CryptographicException` when the envelope is truncated, carries an unknown version, was altered, or was produced under a different key. Text is UTF-8 in both directions and strictly so: a string that is not well-formed UTF-16 (a lone surrogate) is refused by `EncryptToBase64` rather than sealed as U+FFFD, and an envelope whose plaintext is not UTF-8 opens with `Decrypt`, not `DecryptFromBase64`.

## Security

- Keep `Passphrase` in a secret store. A configuration file is not one.
- `Salt` is required and should be long and random. It is what stops a derived key from being precomputable across every deployment sharing a passphrase.
- `Iterations` defaults to 600 000, the OWASP figure for PBKDF2-HMAC-SHA512. Lowering it below 100 000 is refused.
- Passphrase and salt are read as UTF-8, so any alphabet survives them.
- There is no default passphrase and no parameterless registration. Encryption that silently works without configuration is worse than encryption that refuses to start.
- **One key, for the life of the configuration.** There is no key rotation yet: every value is sealed under the key derived from the configured passphrase and salt, and changing either orphans everything sealed before. With a random 96-bit nonce per message, NIST SP 800-38D bounds one key to 2^32 messages before the chance of a repeated nonce stops being negligible; a deployment that seals billions of values needs a key per period, which is the next envelope version's job.

## Supported hash algorithms

`SHA256`, `SHA384`, `SHA512` — used to stretch the passphrase during key derivation.

SHA-1 was removed: it was the only choice here that weakened the derived key, and leaving it selectable meant a configuration file could quietly pick it.

## Upgrading from 1.0.x

Version 1.1.0 changed both the ciphertext format and the API; it should have been a major version, and this table is the apology. **Data encrypted by 1.0.x cannot be read by 1.1.0 or later** and has to be re-encrypted.

| 1.0.x | 1.1.0 and later |
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
