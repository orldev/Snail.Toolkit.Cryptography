namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// Represents the parameters required for symmetric encryption using PBKDF2 key derivation and AES.
/// </summary>
/// <remarks>
/// This class encapsulates all cryptographic parameters needed to perform secure symmetric encryption.
/// All members should be properly initialized before use in cryptographic operations.
/// </remarks>
public class SymEncParams
{
    /// <summary>
    /// Gets or sets the secret passphrase used for key derivation.
    /// </summary>
    /// <value>
    /// The passphrase as a string. Should meet complexity requirements:
    /// - Minimum 12 characters length
    /// - Mix of uppercase, lowercase, numbers, and special characters
    /// - Not based on dictionary words or common patterns
    /// </value>
    /// <example>"CorrectHorseBatteryStaple!"</example>
    public string? Passphrase { get; set; }

    /// <summary>
    /// Gets or sets the hash algorithm name for PBKDF2 key derivation.
    /// </summary>
    /// <value>
    /// The hash algorithm name in "SHA-XXX" format (e.g., "SHA-256", "SHA-384", "SHA-512").
    /// </value>
    /// <remarks>
    /// Stronger hash algorithms provide better security but may impact performance.
    /// SHA-384 or SHA-512 are recommended for new implementations.
    /// </remarks>
    public string? HashAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the number of iterations for PBKDF2 key derivation.
    /// </summary>
    /// <value>
    /// The iteration count. Should be ≥ 100,000 for security-sensitive applications.
    /// </value>
    /// <remarks>
    /// Higher values increase resistance against brute-force attacks but impact performance.
    /// NIST recommends at least 10,000 iterations, but modern systems should use 100,000+.
    /// </remarks>
    public int Iterations { get; set; }

    /// <summary>
    /// Gets or sets the cryptographic salt for key derivation.
    /// </summary>
    /// <value>
    /// A byte array containing random salt. Should be:
    /// - At least 8 bytes (64 bits) in length
    /// - 16 bytes (128 bits) recommended
    /// - Randomly generated for each key derivation
    /// </value>
    /// <remarks>
    /// The salt prevents rainbow table attacks and ensures unique keys even with identical passphrases.
    /// Must be stored securely along with the iteration count for proper key regeneration.
    /// </remarks>
    public byte[]? Salt { get; set; }

    /// <summary>
    /// Gets or sets the desired key length in bytes for the derived encryption key.
    /// </summary>
    /// <value>
    /// The key length in bytes. Common values:
    /// - 16 (128-bit)
    /// - 24 (192-bit)
    /// - 32 (256-bit)
    /// </value>
    /// <remarks>
    /// Must match the requirements of the symmetric algorithm being used.
    /// For AES, 32 bytes (256-bit) provides the strongest security.
    /// </remarks>
    public int DesiredKeyLength { get; set; }

    /// <summary>
    /// Gets or sets the initialization vector (IV) for the encryption operation.
    /// </summary>
    /// <value>
    /// A byte array containing the IV. For AES:
    /// - Must be exactly 16 bytes (128 bits)
    /// - Should be cryptographically random
    /// - Never reused with the same key
    /// </value>
    /// <remarks>
    /// The IV ensures identical plaintexts encrypt to different ciphertexts.
    /// Must be stored/transmitted with the ciphertext (doesn't need to be secret).
    /// </remarks>
    public byte[]? IV { get; set; }
}