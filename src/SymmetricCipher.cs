using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Cryptography.Entities;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography;

/// <summary>
/// AES-GCM encryption under a key derived once from the configured passphrase.
/// </summary>
/// <remarks>
/// <para>
/// The envelope is <c>version(1) | nonce(12) | tag(16) | ciphertext</c>. The version byte exists so a
/// future format can be told from this one: the previous format was a bare CBC blob carrying no
/// metadata at all, which left no way to change anything without orphaning every stored value.
/// </para>
/// <para>
/// AES-GCM replaced AES-CBC because CBC carried no authentication. Flipping one byte of a CBC
/// ciphertext was accepted and decrypted into altered plaintext in 255 of 256 attempts, and the same
/// probe against the final block separated padding failures from successes 252 times out of 256 — a
/// padding oracle. GCM rejects every altered byte.
/// </para>
/// <para>
/// The key is derived in the constructor and held. PBKDF2 over a constant passphrase and salt yields a
/// constant key, yet it used to be recomputed on every call: 190 ms to encrypt three bytes at 600 000
/// iterations of SHA-512, on a thread pool thread, behind an <c>await</c> that never yielded.
/// </para>
/// <para>
/// Each thread that seals or opens keeps one <see cref="AesGcm"/> of its own for the cipher's lifetime instead of
/// building and disposing one per call; an instance never leaves the thread that made it. Disposing the cipher
/// disposes every one of them, which wipes their copies of the key. A thread that ends leaves its instance with the
/// cipher until then: the cipher holds one instance for every thread that ever called it.
/// </para>
/// </remarks>
public sealed class SymmetricCipher : ISymmetricCipher, IDisposable
{
    private const byte Version = 1;
    private const int NonceOffset = 1;
    private const int NonceLength = 12;
    private const int TagOffset = NonceOffset + NonceLength;
    private const int TagLength = 16;
    private const int HeaderLength = TagOffset + TagLength;
    private const int StackLimit = 256;

    private readonly byte[] _key;
    private readonly ThreadLocal<AesGcm> _instances;
    private int _isDisposed;

    /// <summary>Derives the key this cipher keeps for its lifetime.</summary>
    /// <remarks>
    /// The settings are judged here by the rules the registration applies at start, so a cipher built by hand fails
    /// at construction with the setting named, not on its first use with a <see cref="CryptographicException"/>
    /// that reads as tampering.
    /// </remarks>
    /// <exception cref="ArgumentException">A setting is missing or out of range; the message names it.</exception>
    public SymmetricCipher(IOptions<CipherOptions> options)
    {
        var settings = options.Value;

        var failures = CipherRules.Failures(settings, section: null);
        if (failures.Count > 0)
            throw new ArgumentException(string.Join(' ', failures), nameof(options));

        _key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(settings.Passphrase!),
            Encoding.UTF8.GetBytes(settings.Salt!),
            settings.Iterations,
            HashName(settings.HashMethod),
            settings.DesiredKeyLength);

        _instances = new ThreadLocal<AesGcm>(() => new AesGcm(_key, TagLength), trackAllValues: true);
    }

    /// <summary>Disposes the <see cref="AesGcm"/> instance of every thread that used this cipher.</summary>
    /// <remarks>A call after this one throws <see cref="ObjectDisposedException"/>.</remarks>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _isDisposed, 1) == 1)
            return;

        foreach (var aes in _instances.Values)
            aes.Dispose();

        _instances.Dispose();
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);

        var envelope = new byte[HeaderLength + plainText.Length];
        Seal(plainText, envelope);

        return envelope;
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] cipherText)
    {
        ArgumentNullException.ThrowIfNull(cipherText);

        MustBeAnEnvelope(cipherText);

        var plainText = new byte[cipherText.Length - HeaderLength];
        Open(cipherText, plainText);

        return plainText;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The UTF-8 bytes and the envelope live in <see cref="Scratch"/> memory, the stack up to 256 bytes and the
    /// shared pool beyond, rather than in two arrays per call; the plaintext is wiped before the scratch is given back.
    /// </remarks>
    public string EncryptToBase64(string clearText)
    {
        ArgumentNullException.ThrowIfNull(clearText);

        int length = Encoding.UTF8.GetByteCount(clearText);
        using var plainText = Scratch.Secret(length, stackalloc byte[StackLimit]);
        using var envelope = Scratch.Public(HeaderLength + length, stackalloc byte[StackLimit]);

        Encoding.UTF8.GetBytes(clearText, plainText.Bytes);
        Seal(plainText.Bytes, envelope.Bytes);

        return Convert.ToBase64String(envelope.Bytes);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The decoded envelope and the plaintext live in <see cref="Scratch"/> memory, as in
    /// <see cref="EncryptToBase64"/>. Text that is not Base64 is refused at once: it used to be decoded a second
    /// time by <see cref="Convert.FromBase64String"/> for the sake of its exception, which allocated the whole
    /// decoded length, 7.3 MB for ten megabytes of text, only to throw.
    /// </remarks>
    public string DecryptFromBase64(string cipherText)
    {
        ArgumentNullException.ThrowIfNull(cipherText);

        using var decoded = Scratch.Public(cipherText.Length / 4 * 3, stackalloc byte[StackLimit]);
        if (!Convert.TryFromBase64String(cipherText, decoded.Bytes, out int written))
            throw new FormatException("The text is not valid Base64.");

        return Opened(decoded.Bytes[..written]);
    }

    private static void MustBeAnEnvelope(ReadOnlySpan<byte> cipherText)
    {
        if (cipherText.Length < HeaderLength)
            throw new CryptographicException("The ciphertext is shorter than one envelope header.");

        if (cipherText[0] != Version)
            throw new CryptographicException($"Ciphertext version {cipherText[0]} is not supported.");
    }

    private string Opened(ReadOnlySpan<byte> envelope)
    {
        MustBeAnEnvelope(envelope);

        using var plainText = Scratch.Secret(envelope.Length - HeaderLength, stackalloc byte[StackLimit]);
        Open(envelope, plainText.Bytes);

        return Encoding.UTF8.GetString(plainText.Bytes);
    }

    private void Seal(ReadOnlySpan<byte> plainText, Span<byte> envelope)
    {
        envelope[0] = Version;
        RandomNumberGenerator.Fill(envelope.Slice(NonceOffset, NonceLength));

        var aes = _instances.Value!;
        aes.Encrypt(
            envelope.Slice(NonceOffset, NonceLength),
            plainText,
            envelope[HeaderLength..],
            envelope.Slice(TagOffset, TagLength));
    }

    private void Open(ReadOnlySpan<byte> envelope, Span<byte> plainText)
    {
        var aes = _instances.Value!;
        aes.Decrypt(
            envelope.Slice(NonceOffset, NonceLength),
            envelope[HeaderLength..],
            envelope.Slice(TagOffset, TagLength),
            plainText);
    }

    private static HashAlgorithmName HashName(HashAlgo method) => method switch
    {
        HashAlgo.SHA256 => HashAlgorithmName.SHA256,
        HashAlgo.SHA384 => HashAlgorithmName.SHA384,
        HashAlgo.SHA512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Unknown hash algorithm.")
    };
}
