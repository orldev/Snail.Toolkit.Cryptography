using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography;

/// <summary>
/// Provides symmetric encryption/decryption services using AES with PBKDF2 key derivation.
/// </summary>
/// <remarks>
/// This implementation uses:
/// - AES (Advanced Encryption Standard) for symmetric encryption
/// - PBKDF2 (Password-Based Key Derivation Function 2) for key derivation
/// - Configurable parameters via <see cref="SymCryptoOpts"/>
/// </remarks>
/// <param name="options">The configuration options for cryptographic operations</param>
public class SymmetricCipher(IOptions<SymCryptoOpts> options) : ISymmetricCipher
{
    private readonly SymCryptoOpts _options = options.Value;

    /// <summary>
    /// Encrypts the specified byte array using AES encryption.
    /// </summary>
    /// <param name="plainText">The plaintext data to encrypt</param>
    /// <returns>The encrypted ciphertext as byte array</returns>
    /// <exception cref="ArgumentNullException">Thrown when input bytes are null</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    /// <remarks>
    /// Encryption process:
    /// 1. Derives key from configured passphrase using PBKDF2
    /// 2. Uses configured initialization vector (IV)
    /// 3. Output includes both IV and ciphertext (unless configured otherwise)
    /// SECURITY NOTE: Using a static IV reduces security - consider random IVs for production
    /// </remarks>
    public async Task<byte[]> EncryptAsync(byte[] plainText)
    {
        using var aes = Aes.Create();
        aes.Key = DeriveKeyFromPassword(_options.Passphrase);
        aes.IV = InitializationVector(_options.IV);
        
        await using MemoryStream output = new();
        await using CryptoStream cryptoStream = new(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
        await cryptoStream.WriteAsync(plainText);
        await cryptoStream.FlushFinalBlockAsync();
        
        return output.ToArray();
    }
    
    /// <summary>
    /// Decrypts the specified encrypted byte array using AES decryption.
    /// </summary>
    /// <param name="encrypted">The ciphertext data to decrypt</param>
    /// <returns>The decrypted plaintext as byte array</returns>
    /// <exception cref="ArgumentNullException">Thrown when input is null</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (invalid key, corrupted data, etc.)</exception>
    /// <remarks>
    /// Decryption process:
    /// 1. Derives key from configured passphrase using PBKDF2
    /// 2. Uses configured initialization vector (IV)
    /// 3. Returns original plaintext bytes
    /// SECURITY NOTE: Ensure the same IV used for encryption is provided
    /// </remarks>
    public async Task<byte[]> DecryptAsync(byte[] encrypted)
    {
        using var aes = Aes.Create();
        aes.Key = DeriveKeyFromPassword(_options.Passphrase);
        aes.IV = InitializationVector(_options.IV);
        
        await using MemoryStream input = new(encrypted);
        await using CryptoStream cryptoStream = new(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
        await using MemoryStream output = new();
        await cryptoStream.CopyToAsync(output);
        
        return output.ToArray();
    }

    /// <summary>
    /// Encrypts a string and returns the result as a Base64-encoded string.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt</param>
    /// <returns>Base64-encoded ciphertext</returns>
    /// <exception cref="ArgumentNullException">Thrown when input is null</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    /// <remarks>
    /// This method:
    /// 1. Converts string to bytes using Unicode encoding
    /// 2. Encrypts using <see cref="EncryptAsync"/>
    /// 3. Returns result as Base64 string
    /// Suitable for text-based storage/transmission
    /// </remarks>
    public async Task<string> EncryptToBase64Async(string clearText)
    {
        var bytes = Encoding.Unicode.GetBytes(clearText);
        var encrypt = await EncryptAsync(bytes);
        return Convert.ToBase64String(encrypt);
    }

    /// <summary>
    /// Decrypts a Base64-encoded ciphertext string back to its original plaintext.
    /// </summary>
    /// <param name="encrypted">Base64-encoded ciphertext</param>
    /// <returns>The decrypted plaintext string</returns>
    /// <exception cref="ArgumentNullException">Thrown when input is null</exception>
    /// <exception cref="FormatException">Thrown when input is not valid Base64</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails</exception>
    /// <remarks>
    /// This method:
    /// 1. Converts Base64 string to bytes
    /// 2. Decrypts using <see cref="DecryptAsync"/>
    /// 3. Returns result as Unicode string
    /// Counterpart to <see cref="EncryptToBase64Async"/>
    /// </remarks>
    public async Task<string> DecryptFromBase64Async(string encrypted)
    {
        var bytes = Convert.FromBase64String(encrypted);
        var decrypt = await DecryptAsync(bytes);
        return Encoding.Unicode.GetString(decrypt);
    }

    /// <summary>
    /// Derives a cryptographic key from a password using PBKDF2.
    /// </summary>
    /// <param name="password">The password to derive key from</param>
    /// <returns>Derived key as byte array</returns>
    /// <remarks>
    /// Key derivation parameters:
    /// - Uses configured salt (or empty if not specified)
    /// - Applies configured iteration count
    /// - Produces key of configured length
    /// - Uses specified hash algorithm
    /// SECURITY NOTE: Default empty salt significantly reduces security
    /// </remarks>
    private byte[] DeriveKeyFromPassword(string password)
    {
        var emptySalt = string.IsNullOrEmpty(_options.Salt) ? [] : Encoding.ASCII.GetBytes(_options.Salt);
        var iterations = _options.Iterations;
        var desiredKeyLength = _options.DesiredKeyLength;
        var hashMethod = new HashAlgorithmName(_options.HashMethod.ToString());
        
        return Rfc2898DeriveBytes.Pbkdf2(Encoding.Unicode.GetBytes(password),
            emptySalt,
            iterations,
            hashMethod,
            desiredKeyLength);
    }
    
    /// <summary>
    /// Generates or parses an initialization vector (IV) for AES operations.
    /// </summary>
    /// <param name="iv">Optional IV string</param>
    /// <returns>IV as byte array</returns>
    /// <remarks>
    /// SECURITY WARNING:
    /// - Default IV is hardcoded and INSECURE for production use
    /// - IV should be random and unique for each encryption
    /// - In production, always specify a proper IV in options
    /// - Consider generating a new random IV for each encryption operation
    /// </remarks>
    private static byte[] InitializationVector(string? iv)
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