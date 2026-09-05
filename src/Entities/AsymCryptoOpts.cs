namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// Represents configuration options for asymmetric cryptography operations.
/// </summary>
public class AsymCryptoOpts
{
    /// <summary>
    /// Gets or sets the length of the RSA modulus in bits.
    /// </summary>
    /// <value>
    /// The modulus length in bits. Default is 2048 bits.
    /// Higher values provide more security but impact performance.
    /// Common secure values are 2048, 3072, or 4096 bits.
    /// </value>
    /// <remarks>
    /// NIST recommends 2048 bits as minimum for new systems through 2030.
    /// </remarks>
    public int ModulusLengthInBits { get; set; } = 2048;

    /// <summary>
    /// Gets or sets the hash algorithm to be used in cryptographic operations.
    /// </summary>
    /// <value>
    /// The hash algorithm. Default is <see cref="HashAlgo.SHA384"/>.
    /// </value>
    /// <remarks>
    /// SHA-384 is recommended for most cases as it provides a good balance
    /// between security and performance. SHA-512 may be used for higher security
    /// requirements, while SHA-256 may be sufficient for some applications.
    /// </remarks>
    public HashAlgo HashMethod { get; set; } = HashAlgo.SHA384;
}