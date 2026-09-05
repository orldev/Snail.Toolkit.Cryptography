namespace Snail.Toolkit.Cryptography.Interfaces;

/// <summary>
/// Defines a service for performing symmetric encryption and decryption operations.
/// </summary>
/// <remarks>
/// This interface provides asynchronous methods for encrypting and decrypting data
/// using symmetric key algorithms (typically AES). It supports both raw byte array
/// and Base64-encoded string formats.
/// </remarks>
public interface ISymmetricCipher
{
    /// <summary>
    /// Encrypts the specified byte array and returns the ciphertext as a byte array.
    /// </summary>
    /// <param name="plainText">The plaintext byte array to encrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the encrypted ciphertext as a byte array.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plainText"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    /// <remarks>
    /// This method is suitable for binary data encryption. The output includes both
    /// the IV and ciphertext in a single byte array.
    /// </remarks>
    Task<byte[]> EncryptAsync(byte[] plainText);

    /// <summary>
    /// Encrypts the specified plaintext string and returns the ciphertext as a Base64-encoded string.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the encrypted ciphertext as a Base64-encoded string.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clearText"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    /// <remarks>
    /// This method is convenient for scenarios where the ciphertext needs to be
    /// stored or transmitted as text (e.g., in JSON, XML, or URLs).
    /// The output includes both the IV and ciphertext encoded as a single Base64 string.
    /// </remarks>
    Task<string> EncryptToBase64Async(string clearText);

    /// <summary>
    /// Decrypts the specified encrypted byte array and returns the original plaintext as a byte array.
    /// </summary>
    /// <param name="encrypted">The encrypted byte array to decrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the decrypted plaintext as a byte array.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encrypted"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="encrypted"/> is empty or malformed.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (invalid key, corrupted data, etc.).</exception>
    /// <remarks>
    /// This method is the counterpart to <see cref="EncryptAsync"/>, handling binary ciphertext
    /// that was produced by the encryption method.
    /// </remarks>
    Task<byte[]> DecryptAsync(byte[] encrypted);

    /// <summary>
    /// Decrypts the specified Base64-encoded ciphertext and returns the original plaintext.
    /// </summary>
    /// <param name="encrypted">The Base64-encoded ciphertext string to decrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the decrypted plaintext string.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encrypted"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="encrypted"/> is empty or malformed.</exception>
    /// <exception cref="FormatException">Thrown when the input is not valid Base64.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (invalid key, corrupted data, etc.).</exception>
    /// <remarks>
    /// This method is the counterpart to <see cref="EncryptToBase64Async"/>, handling
    /// ciphertext that was encoded as Base64 for text-based storage or transmission.
    /// </remarks>
    Task<string> DecryptFromBase64Async(string encrypted);
}