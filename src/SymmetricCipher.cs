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
/// A few <see cref="AesGcm"/> instances are kept idle and lent to whichever thread seals or opens, one call at a
/// time, instead of one being built and disposed per call or one being kept per thread. One per thread held an
/// instance, with its native key handle, for every thread that had ever called the cipher: a thousand short-lived
/// threads left a thousand instances behind until the cipher was disposed. At most <see cref="IdleLimit"/> wait
/// idle; an instance that comes back to a full pool is disposed. Disposing the cipher disposes the idle instances and
/// wipes the derived key, and an instance lent out at that moment is disposed when its call returns it.
/// </para>
/// <para>
/// Text goes through strict UTF-8 in both directions: a lone surrogate used to be sealed as U+FFFD without a word,
/// so the text that came back was not the text that went in. An encryption is lossless or it refuses.
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
    private const int IdleLimit = 16;

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly byte[] _key;
    private readonly AesGcm?[] _idle = new AesGcm?[IdleLimit];
    private int _isDisposed;

    /// <summary>Derives the key this cipher keeps for its lifetime.</summary>
    /// <remarks>
    /// The settings are judged here by the rules the registration applies at start, so a cipher built by hand fails
    /// at construction with the setting named, not on its first use with a <see cref="CryptographicException"/>
    /// that reads as tampering.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">A setting is missing or out of range; the message names it.</exception>
    public SymmetricCipher(IOptions<CipherOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = options.Value;
        var failures = CipherRules.Failures(settings, section: null);
        if (failures.Count > 0)
            throw new ArgumentException(string.Join(' ', failures), nameof(options));

        _key = Rfc2898DeriveBytes.Pbkdf2(
            Utf8.GetBytes(settings.Passphrase!),
            Utf8.GetBytes(settings.Salt!),
            settings.Iterations,
            HashName(settings.HashMethod),
            settings.DesiredKeyLength);
    }

    /// <summary>Disposes the idle <see cref="AesGcm"/> instances and wipes the derived key.</summary>
    /// <remarks>
    /// A call after this one throws <see cref="ObjectDisposedException"/>. An instance lent out at this moment
    /// finishes its call and is disposed when it comes back.
    /// </remarks>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _isDisposed, 1) == 1)
            return;

        for (int slot = 0; slot < _idle.Length; slot++)
            Interlocked.Exchange(ref _idle[slot], null)?.Dispose();

        CryptographicOperations.ZeroMemory(_key);
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

        int length = Utf8.GetByteCount(clearText);
        using var plainText = Scratch.Secret(length, stackalloc byte[StackLimit]);
        using var envelope = Scratch.Public(HeaderLength + length, stackalloc byte[StackLimit]);

        Utf8.GetBytes(clearText, plainText.Bytes);
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

        return Utf8.GetString(plainText.Bytes);
    }

    private void Seal(ReadOnlySpan<byte> plainText, Span<byte> envelope)
    {
        envelope[0] = Version;
        RandomNumberGenerator.Fill(envelope.Slice(NonceOffset, NonceLength));

        var aes = Rent();
        try
        {
            aes.Encrypt(
                envelope.Slice(NonceOffset, NonceLength),
                plainText,
                envelope[HeaderLength..],
                envelope.Slice(TagOffset, TagLength));
        }
        finally
        {
            Return(aes);
        }
    }

    private void Open(ReadOnlySpan<byte> envelope, Span<byte> plainText)
    {
        var aes = Rent();
        try
        {
            aes.Decrypt(
                envelope.Slice(NonceOffset, NonceLength),
                envelope[HeaderLength..],
                envelope.Slice(TagOffset, TagLength),
                plainText);
        }
        finally
        {
            Return(aes);
        }
    }

    /// <summary>An idle instance, or a new one under the key.</summary>
    /// <remarks>
    /// A new instance is checked against disposal once more after it is built, with a full fence: a thread that
    /// passed the first check while another thread disposed the cipher would otherwise copy a key being wiped and
    /// seal an envelope nobody can open, without an error. The second check sees the disposal whenever the key
    /// reads could have overlapped the wipe.
    /// </remarks>
    private AesGcm Rent()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);

        for (int slot = 0; slot < _idle.Length; slot++)
        {
            var idle = Interlocked.Exchange(ref _idle[slot], null);
            if (idle is not null)
                return idle;
        }

        var made = new AesGcm(_key, TagLength);
        if (Interlocked.CompareExchange(ref _isDisposed, 0, 0) == 1)
        {
            made.Dispose();
            throw new ObjectDisposedException(GetType().FullName);
        }

        return made;
    }

    /// <summary>Puts an instance back to wait idle, or disposes it when the pool is full or the cipher is gone.</summary>
    /// <remarks>
    /// The disposal flag is read again after the instance is stored: a disposal that ran between the two reads
    /// has already emptied the slots, so the instance is taken out and disposed here instead of waiting forever.
    /// </remarks>
    private void Return(AesGcm aes)
    {
        for (int slot = 0; slot < _idle.Length; slot++)
        {
            if (Interlocked.CompareExchange(ref _idle[slot], aes, null) is not null)
                continue;

            if (Volatile.Read(ref _isDisposed) == 1)
                Interlocked.Exchange(ref _idle[slot], null)?.Dispose();

            return;
        }

        aes.Dispose();
    }

    private static HashAlgorithmName HashName(HashAlgo method) => method switch
    {
        HashAlgo.SHA256 => HashAlgorithmName.SHA256,
        HashAlgo.SHA384 => HashAlgorithmName.SHA384,
        HashAlgo.SHA512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Unknown hash algorithm.")
    };
}
