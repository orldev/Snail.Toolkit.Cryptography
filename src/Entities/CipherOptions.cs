namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// The secret and the key-derivation parameters <see cref="Interfaces.ISymmetricCipher"/> runs on.
/// </summary>
/// <remarks>
/// There is no initialization vector here any more. AES-GCM draws a fresh nonce for every message and
/// writes it into the ciphertext, which is what makes two encryptions of the same text differ; a
/// configured IV made them identical and leaked equality of plaintexts. An <c>IV</c> key left in an
/// existing configuration section is simply ignored.
/// </remarks>
public sealed class CipherOptions
{
    /// <summary>The configuration section these settings are bound from by default.</summary>
    public const string SectionName = "Cryptography";

    /// <summary>The secret the encryption key is derived from.</summary>
    /// <remarks>
    /// Belongs in a secret store, not in <c>appsettings.json</c>. It is read as UTF-8, so any alphabet
    /// survives it; the previous ASCII reading turned every non-ASCII character into a question mark.
    /// </remarks>
    public string? Passphrase { get; set; }

    /// <summary>The salt mixed into key derivation.</summary>
    /// <remarks>
    /// Required, and read as UTF-8. It used to default to empty, which made the derived key a pure
    /// function of the passphrase and so precomputable across every deployment sharing one.
    /// </remarks>
    public string? Salt { get; set; }

    /// <summary>How many PBKDF2 rounds the passphrase is stretched through.</summary>
    /// <remarks>
    /// Defaults to the OWASP figure for PBKDF2-HMAC-SHA512 rather than the former 1000, which was three
    /// orders of magnitude short of what this type's own documentation demanded. The cost is paid once,
    /// when the cipher is constructed, not per operation.
    /// </remarks>
    public int Iterations { get; set; } = 600_000;

    /// <summary>The derived key length in bytes: 16, 24 or 32.</summary>
    public int DesiredKeyLength { get; set; } = 32;

    /// <summary>The hash PBKDF2 stretches the passphrase through.</summary>
    public HashAlgo HashMethod { get; set; } = HashAlgo.SHA512;
}
