namespace Snail.Toolkit.Cryptography.Entities;

/// <summary>
/// Specifies the byte lengths of hash outputs for various cryptographic hash algorithms.
/// </summary>
/// <remarks>
/// These values represent the fixed output size (in bytes) for each hash algorithm.
/// Useful for buffer allocation and hash size validation.
/// </remarks>
public enum HashAlgoLengths
{
     /// <summary>
     /// SHA-1 algorithm output length (20 bytes / 160 bits)
     /// </summary>
     /// <remarks>
     /// Note: SHA-1 is cryptographically weak and should not be used for security-sensitive applications.
     /// </remarks>
     [Obsolete("SHA-1 is no longer considered secure for cryptographic purposes", false)]
     SHA1 = 20,

     /// <summary>
     /// SHA-256 algorithm output length (32 bytes / 256 bits)
     /// </summary>
     /// <remarks>
     /// Standard secure hash length for most applications. FIPS 180-4 approved.
     /// </remarks>
     SHA256 = 32,

     /// <summary>
     /// SHA-384 algorithm output length (48 bytes / 384 bits)
     /// </summary>
     /// <remarks>
     /// Provides stronger security than SHA-256 while being more performant than SHA-512.
     /// Commonly used in TLS implementations.
     /// </remarks>
     SHA384 = 48,

     /// <summary>
     /// SHA-512 algorithm output length (64 bytes / 512 bits)
     /// </summary>
     /// <remarks>
     /// Maximum security level among SHA-2 family algorithms.
     /// Suitable for applications requiring long-term security guarantees.
     /// </remarks>
     SHA512 = 64,
}