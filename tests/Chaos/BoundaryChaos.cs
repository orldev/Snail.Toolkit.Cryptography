using System.Text;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Tests.Chaos;

/// <summary>
/// Inputs at the edges: text that is not quite text, Base64 that is not quite Base64, sizes far from the benchmarks.
/// </summary>
public class BoundaryChaos
{
    private readonly ISymmetricCipher _cipher = Ciphers.Cipher();

    /// <summary>
    /// A lone surrogate is not valid UTF-16. The default UTF-8 encoder used to replace it with U+FFFD without a
    /// word, so the value that came back was not the value that went in: an encryption lossy in silence. It has to
    /// refuse instead.
    /// </summary>
    [Fact]
    public void EncryptToBase64_ALoneSurrogate_IsRefused()
    {
        const string text = "price \uD800 unknown";

        Assert.ThrowsAny<ArgumentException>(() => _cipher.EncryptToBase64(text));
    }

    /// <summary>
    /// An envelope sealed from arbitrary bytes is not text; opening it as text has to say so rather than hand back
    /// replacement characters.
    /// </summary>
    [Fact]
    public void DecryptFromBase64_AnEnvelopeOfBytesThatAreNotText_IsRefused()
    {
        string sealedBytes = Convert.ToBase64String(_cipher.Encrypt([0xFF, 0xFE, 0xFD]));

        Assert.ThrowsAny<ArgumentException>(() => _cipher.DecryptFromBase64(sealedBytes));
    }

    /// <summary>
    /// A legacy store that line-wraps Base64 at 76 columns hands the wrapped text back; the decoder has to take it.
    /// </summary>
    [Fact]
    public void DecryptFromBase64_LineWrappedBase64_RoundTrips()
    {
        string text = new('x', 500);
        string wrapped = Convert.ToBase64String(_cipher.Encrypt(Encoding.UTF8.GetBytes(text)), Base64FormattingOptions.InsertLineBreaks);

        Assert.Equal(text, _cipher.DecryptFromBase64(wrapped));
    }

    /// <summary>
    /// An envelope sealed by the text path is the same envelope as the byte path's; both have to open either.
    /// </summary>
    [Fact]
    public void Decrypt_EnvelopeFromEncryptToBase64_OpensAsBytes()
    {
        byte[] envelope = Convert.FromBase64String(_cipher.EncryptToBase64("crossing paths"));

        Assert.Equal("crossing paths", Encoding.UTF8.GetString(_cipher.Decrypt(envelope)));
    }

    /// <summary>
    /// Invalid Base64 is decoded twice: once into the rented scratch, which refuses it, then again by
    /// Convert.FromBase64String, which allocates the whole decoded size only to throw. Refusing ten megabytes
    /// of garbage should cost nothing once the scratch is warm.
    /// </summary>
    [Fact]
    public void DecryptFromBase64_TenMegabytesOfInvalidBase64_AllocatesNothingToRefuse()
    {
        string valid = Convert.ToBase64String(_cipher.Encrypt(new byte[7 * 1024 * 1024]));
        string garbage = string.Concat(valid.AsSpan(0, valid.Length - 4), "!!!!");
        _cipher.DecryptFromBase64(valid);

        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<FormatException>(() => _cipher.DecryptFromBase64(garbage));
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(allocated < 1024 * 1024, $"Refusing {garbage.Length} characters of invalid Base64 allocated {allocated} bytes.");
    }

    /// <summary>
    /// One hundred megabytes in one envelope: the array paths allocate the output once and nothing else.
    /// </summary>
    [Fact]
    public void Encrypt_OneHundredMegabytes_RoundTrips()
    {
        var plainText = new byte[100 * 1024 * 1024];
        plainText[0] = 1;
        plainText[^1] = 2;

        byte[] opened = _cipher.Decrypt(_cipher.Encrypt(plainText));

        Assert.True(opened.AsSpan().SequenceEqual(plainText));
    }

    /// <summary>
    /// Sixteen threads, ten thousand round trips each, over the one cipher: every envelope opens, and the
    /// AES-GCM instance of one thread is never touched by another.
    /// </summary>
    [Fact]
    public void Encrypt_SixteenThreadsTenThousandRoundTripsEach_EveryEnvelopeOpens()
    {
        int failures = 0;

        Parallel.For(0, 16, worker =>
        {
            for (int round = 0; round < 10_000; round++)
            {
                string text = $"{worker}:{round}";

                if (_cipher.DecryptFromBase64(_cipher.EncryptToBase64(text)) != text)
                    Interlocked.Increment(ref failures);
            }
        });

        Assert.Equal(0, failures);
    }
}
