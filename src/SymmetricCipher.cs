using System.Buffers;
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
    /// <exception cref="ArgumentException">The passphrase or the salt is missing.</exception>
    public SymmetricCipher(IOptions<CipherOptions> options)
    {
        var settings = options.Value;

        ArgumentException.ThrowIfNullOrWhiteSpace(settings.Passphrase, nameof(CipherOptions.Passphrase));
        ArgumentException.ThrowIfNullOrWhiteSpace(settings.Salt, nameof(CipherOptions.Salt));

        _key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(settings.Passphrase),
            Encoding.UTF8.GetBytes(settings.Salt),
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
    /// The UTF-8 bytes and the envelope live in scratch memory — the stack up to 256 bytes, the shared pool
    /// beyond — rather than in two arrays per call, and the plaintext is wiped before the scratch is given back.
    /// </remarks>
    public string EncryptToBase64(string clearText)
    {
        ArgumentNullException.ThrowIfNull(clearText);

        int length = Encoding.UTF8.GetByteCount(clearText);
        byte[]? pooledText = length > StackLimit ? ArrayPool<byte>.Shared.Rent(length) : null;
        byte[]? pooledEnvelope = HeaderLength + length > StackLimit ? ArrayPool<byte>.Shared.Rent(HeaderLength + length) : null;
        Span<byte> plainText = (pooledText ?? stackalloc byte[StackLimit])[..length];
        Span<byte> envelope = (pooledEnvelope ?? stackalloc byte[StackLimit])[..(HeaderLength + length)];

        try
        {
            Encoding.UTF8.GetBytes(clearText, plainText);
            Seal(plainText, envelope);

            return Convert.ToBase64String(envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainText);
            Return(pooledText);
            Return(pooledEnvelope);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// The decoded envelope and the plaintext live in scratch memory, as in <see cref="EncryptToBase64"/>. Text
    /// that does not decode is handed to <see cref="Convert.FromBase64String"/>, so it is refused with the very
    /// exception it always was.
    /// </remarks>
    public string DecryptFromBase64(string cipherText)
    {
        ArgumentNullException.ThrowIfNull(cipherText);

        int capacity = cipherText.Length / 4 * 3;
        byte[]? pooledEnvelope = capacity > StackLimit ? ArrayPool<byte>.Shared.Rent(capacity) : null;
        Span<byte> decoded = (pooledEnvelope ?? stackalloc byte[StackLimit])[..capacity];

        try
        {
            if (!Convert.TryFromBase64String(cipherText, decoded, out int written))
                return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(cipherText)));

            return Opened(decoded[..written]);
        }
        finally
        {
            Return(pooledEnvelope);
        }
    }

    private static void MustBeAnEnvelope(ReadOnlySpan<byte> cipherText)
    {
        if (cipherText.Length < HeaderLength)
            throw new CryptographicException("The ciphertext is shorter than one envelope header.");

        if (cipherText[0] != Version)
            throw new CryptographicException($"Ciphertext version {cipherText[0]} is not supported.");
    }

    private static void Return(byte[]? pooled)
    {
        if (pooled is not null)
            ArrayPool<byte>.Shared.Return(pooled);
    }

    private string Opened(ReadOnlySpan<byte> envelope)
    {
        MustBeAnEnvelope(envelope);

        int length = envelope.Length - HeaderLength;
        byte[]? pooledText = length > StackLimit ? ArrayPool<byte>.Shared.Rent(length) : null;
        Span<byte> plainText = (pooledText ?? stackalloc byte[StackLimit])[..length];

        try
        {
            Open(envelope, plainText);

            return Encoding.UTF8.GetString(plainText);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainText);
            Return(pooledText);
        }
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
