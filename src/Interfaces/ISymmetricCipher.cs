using System.Security.Cryptography;

namespace Snail.Toolkit.Cryptography.Interfaces;

/// <summary>
/// Authenticated symmetric encryption over bytes and Base64 text.
/// </summary>
/// <remarks>
/// The operations are synchronous because they are pure CPU work over memory. They were asynchronous,
/// which allocated a state machine and a task per call, completed synchronously anyway, and hid the one
/// cost that genuinely blocked a thread — key derivation, now paid once at construction.
/// </remarks>
public interface ISymmetricCipher
{
    /// <summary>Encrypts bytes into a self-describing envelope.</summary>
    /// <remarks>
    /// The result carries its own version byte, nonce and authentication tag, so it can be stored on its
    /// own and decrypted without any out-of-band parameter.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="plainText"/> is null.</exception>
    byte[] Encrypt(byte[] plainText);

    /// <summary>Decrypts an envelope produced by <see cref="Encrypt"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="cipherText"/> is null.</exception>
    /// <exception cref="CryptographicException">
    /// The envelope is truncated, carries an unknown version, or fails authentication because it was
    /// altered or was produced under a different key.
    /// </exception>
    byte[] Decrypt(byte[] cipherText);

    /// <summary>Encrypts text and returns the envelope as Base64.</summary>
    /// <remarks>The text is sealed as UTF-8, strictly: what cannot be carried is refused, never replaced.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="clearText"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="clearText"/> is not well-formed UTF-16, such as a lone surrogate.</exception>
    string EncryptToBase64(string clearText);

    /// <summary>Decrypts Base64 produced by <see cref="EncryptToBase64"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="cipherText"/> is null.</exception>
    /// <exception cref="FormatException"><paramref name="cipherText"/> is not valid Base64.</exception>
    /// <exception cref="CryptographicException">The envelope is truncated, unknown or fails authentication.</exception>
    /// <exception cref="ArgumentException">The plaintext is not UTF-8 text: the envelope was sealed from bytes and opens with <see cref="Decrypt"/>.</exception>
    string DecryptFromBase64(string cipherText);
}
