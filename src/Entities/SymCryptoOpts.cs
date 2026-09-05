using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// Represents configuration options for symmetric cryptography operations using AES.
/// </summary>
/// <remarks>
/// This class provides settings for password-based key derivation (PBKDF2) and
/// AES encryption parameters. Proper configuration is critical for security.
/// </remarks>
public class SymCryptoOpts
{
    /// <summary>
    /// Gets or sets the passphrase used for key derivation.
    /// </summary>
    /// <value>
    /// The secret passphrase. Should be sufficiently complex and kept confidential.
    /// </value>
    /// <remarks>
    /// For security, prefer passphrases with:
    /// - Minimum 12 characters
    /// - Upper/lower case letters
    /// - Numbers and special characters
    /// - No dictionary words
    /// </remarks>
    [AllowNull]
    public string Passphrase { get; set; }

    /// <summary>
    /// Gets or sets the initialization vector (IV) for AES encryption.
    /// </summary>
    /// <value>
    /// A base64 or hex-encoded string representing the IV. 
    /// If null, a default IV will be used (not recommended for production).
    /// </value>
    /// <remarks>
    /// The IV should be:
    /// - Randomly generated for each encryption operation
    /// - 16 bytes (128 bits) for AES
    /// - Never reused with the same key
    /// - Transmitted/stored with the ciphertext
    /// </remarks>
    public string? IV { get; set; }

    /// <summary>
    /// Gets or sets the salt value for key derivation.
    /// </summary>
    /// <value>
    /// A base64 or hex-encoded string representing the salt.
    /// If null, a default salt will be used (not recommended for production).
    /// </value>
    /// <remarks>
    /// The salt should be:
    /// - Randomly generated
    /// - At least 8 bytes (64 bits), preferably 16 bytes
    /// - Unique per passphrase
    /// - Stored with the derived key
    /// </remarks>
    public string? Salt { get; set; }

    /// <summary>
    /// Gets or sets the number of iterations for PBKDF2 key derivation.
    /// </summary>
    /// <value>
    /// The iteration count. Default is 1000 (consider increasing for better security).
    /// </value>
    /// <remarks>
    /// Higher values increase security by making brute-force attacks slower.
    /// Recommended values:
    /// - Minimum 100,000 for interactive logins
    /// - 600,000+ for sensitive data
    /// - Balance security needs with performance requirements
    /// </remarks>
    public int Iterations { get; set; } = 1000;

    /// <summary>
    /// Gets or sets the desired key length in bytes.
    /// </summary>
    /// <value>
    /// The key length in bytes. Default is 16 (128-bit AES key).
    /// </value>
    /// <remarks>
    /// Common values:
    /// - 16 (128-bit) - Basic security
    /// - 24 (192-bit) - Stronger security
    /// - 32 (256-bit) - Maximum AES security
    /// Note: Must match your AES variant's requirements.
    /// </remarks>
    public int DesiredKeyLength { get; set; } = 16;

    /// <summary>
    /// Gets or sets the hash algorithm used for key derivation.
    /// </summary>
    /// <value>
    /// The hash algorithm. Default is <see cref="HashAlgo.SHA384"/>.
    /// </value>
    public HashAlgo HashMethod { get; set; } = HashAlgo.SHA384;

    /// <summary>
    /// Creates a <see cref="SymEncParams"/> instance from the current configuration.
    /// </summary>
    /// <returns>A configured <see cref="SymEncParams"/> object.</returns>
    /// <remarks>
    /// Performs conversion of string parameters to byte arrays.
    /// Uses default values for null/empty IV and salt (not recommended for production).
    /// </remarks>
    public SymEncParams CreateParams()
    {
        return new SymEncParams
        {
            Passphrase = Passphrase,
            HashAlgorithm = $"SHA-{HashMethod:D}",
            Iterations = Iterations,
            Salt = GetBytes(Salt),
            DesiredKeyLength = DesiredKeyLength,
            IV = GetBytes(IV)
        };
    }

    /// <summary>
    /// Converts a string to bytes, falling back to a default value if null/empty.
    /// </summary>
    /// <param name="iv">The input string (IV or salt).</param>
    /// <returns>Byte array representation of the input.</returns>
    /// <remarks>
    /// WARNING: The default value provides no cryptographic security and should
    /// only be used for testing/development purposes.
    /// </remarks>
    private static byte[] GetBytes(string? iv)
    {
        return string.IsNullOrEmpty(iv)
            ?
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
            ]
            : Encoding.ASCII.GetBytes(iv);
    }
}