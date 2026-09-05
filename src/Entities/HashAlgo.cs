namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// Specifies cryptographic hash algorithms available for security operations.
/// </summary>
/// <remarks>
/// When selecting a hash algorithm, consider security requirements and performance characteristics.
/// Modern applications should prefer SHA-2 (SHA256, SHA384, SHA512) or SHA-3 family algorithms.
/// </remarks>
public enum HashAlgo
{
    // /// <summary>
    // /// MD5 algorithm (128-bit hash) - INSECURE, provided only for legacy compatibility.
    // /// </summary>
    // /// <remarks>
    // /// MD5 is cryptographically broken and unsuitable for security purposes.
    // /// Use only for non-cryptographic purposes like checksums.
    // /// </remarks>
    // [Obsolete("MD5 is cryptographically broken and should not be used for security purposes", error: false)]
    // MD5,
    
    /// <summary>
    /// SHA-1 algorithm (160-bit hash) - WEAK SECURITY, provided for legacy compatibility.
    /// </summary>
    /// <remarks>
    /// SHA-1 is considered cryptographically weak. NIST deprecated its use in 2011.
    /// Use only when required for backward compatibility.
    /// </remarks>
    [Obsolete("SHA-1 is no longer considered secure for cryptographic purposes", error: false)]
    SHA1 = 1,

    /// <summary>
    /// SHA-2 algorithm with 256-bit hash output (recommended for most applications).
    /// </summary>
    /// <remarks>
    /// Provides good security for most purposes. FIPS 180-4 approved.
    /// Suitable for digital signatures, certificate hashing, and general security applications.
    /// </remarks>
    SHA256 = 256,

    /// <summary>
    /// SHA-2 algorithm with 384-bit hash output (higher security alternative).
    /// </summary>
    /// <remarks>
    /// Recommended when stronger security than SHA-256 is needed while maintaining
    /// better performance than SHA-512. Often used in TLS/SSL implementations.
    /// </remarks>
    SHA384 = 384,

    /// <summary>
    /// SHA-2 algorithm with 512-bit hash output (maximum SHA-2 security).
    /// </summary>
    /// <remarks>
    /// Provides the highest security level among SHA-2 algorithms.
    /// Suitable for applications requiring long-term security or protecting sensitive data.
    /// </remarks>
    SHA512 = 512,

    // /// <summary>
    // /// SHA-3 algorithm with 256-bit hash output (next-generation standard).
    // /// </summary>
    // /// <remarks>
    // /// Part of the Keccak family, standardized as FIPS 202 in 2015.
    // /// Provides security characteristics different from SHA-2 family.
    // /// </remarks>
    // SHA3_256,
    
    // /// <summary>
    // /// SHA-3 algorithm with 384-bit hash output (next-generation standard).
    // /// </summary>
    // SHA3_384,
    
    // /// <summary>
    // /// SHA-3 algorithm with 512-bit hash output (next-generation standard).
    // /// </summary>
    // SHA3_512
}