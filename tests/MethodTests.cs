using System.Security.Cryptography;
using System.Text;
using Snail.Toolkit.Cryptography.Interfaces;

namespace Snail.Toolkit.Cryptography.Tests;

public class MethodTests
{
    private readonly ISymmetricCipher _cipher = Helper.Cipher();

    [Fact]
    public void Encrypt_RoundTrip_ReturnsTheOriginalBytes()
    {
        byte[] plainText = [1, 2, 3, 4, 5];

        var decrypted = _cipher.Decrypt(_cipher.Encrypt(plainText));

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void EncryptToBase64_RoundTrip_ReturnsTheOriginalText()
    {
        const string text = "Hello world";

        Assert.Equal(text, _cipher.DecryptFromBase64(_cipher.EncryptToBase64(text)));
    }

    [Fact]
    public void EncryptToBase64_TextOutsideTheBasicPlane_RoundTrips()
    {
        const string text = "Привет 👨‍👩‍👧‍👦 \U0001F600";

        Assert.Equal(text, _cipher.DecryptFromBase64(_cipher.EncryptToBase64(text)));
    }

    [Fact]
    public void Encrypt_EmptyInput_RoundTripsToEmpty()
    {
        Assert.Empty(_cipher.Decrypt(_cipher.Encrypt([])));
    }

    /// <summary>
    /// The former fixed IV made this equality hold, which leaked that two stored values were the same.
    /// </summary>
    [Fact]
    public void Encrypt_TheSamePlaintextTwice_ProducesDifferentCiphertexts()
    {
        Assert.NotEqual(_cipher.EncryptToBase64("same message"), _cipher.EncryptToBase64("same message"));
    }

    /// <summary>
    /// Every single-byte alteration has to be refused. Under AES-CBC 255 of these 256 were accepted and
    /// decrypted into altered plaintext, and altering the final block instead produced a padding oracle.
    /// </summary>
    [Fact]
    public void Decrypt_AlteredCiphertext_Throws()
    {
        var cipherText = _cipher.Encrypt(Encoding.UTF8.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

        foreach (var position in (int[])[1, 5, cipherText.Length / 2, cipherText.Length - 1])
        {
            var altered = (byte[])cipherText.Clone();
            altered[position] ^= 0xFF;

            Assert.ThrowsAny<CryptographicException>(() => _cipher.Decrypt(altered));
        }
    }

    [Fact]
    public void Decrypt_TruncatedEnvelope_Throws()
    {
        var cipherText = _cipher.Encrypt([1, 2, 3]);

        Assert.Throws<CryptographicException>(() => _cipher.Decrypt(cipherText[..10]));
    }

    [Fact]
    public void Decrypt_UnknownEnvelopeVersion_Throws()
    {
        var cipherText = _cipher.Encrypt([1, 2, 3]);
        cipherText[0] = 99;

        var error = Assert.Throws<CryptographicException>(() => _cipher.Decrypt(cipherText));

        Assert.Contains("99", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Decrypt_CiphertextFromAnotherPassphrase_Throws()
    {
        var other = Helper.Cipher(options =>
        {
            Helper.Defaults(options);
            options.Passphrase = "a different secret";
        });

        var cipherText = _cipher.Encrypt(Encoding.UTF8.GetBytes("secret"));

        Assert.ThrowsAny<CryptographicException>(() => other.Decrypt(cipherText));
    }

    [Fact]
    public void Decrypt_Empty_Throws()
    {
        Assert.Throws<CryptographicException>(() => _cipher.Decrypt([]));
    }

    [Fact]
    public void DecryptFromBase64_EmptyText_Throws()
    {
        Assert.Throws<CryptographicException>(() => _cipher.DecryptFromBase64(""));
    }

    [Fact]
    public void DecryptFromBase64_TextThatIsNotBase64_Throws()
    {
        Assert.Throws<FormatException>(() => _cipher.DecryptFromBase64("not base64 at all!"));
    }

    [Fact]
    public void Encrypt_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _cipher.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _cipher.Decrypt(null!));
    }

    /// <summary>
    /// A non-ASCII salt used to collapse to a run of question marks, so two different salts derived one key.
    /// </summary>
    [Fact]
    public void Encrypt_TwoDifferentNonAsciiSalts_ProduceKeysThatCannotReadEachOther()
    {
        var first = Helper.Cipher(options =>
        {
            Helper.Defaults(options);
            options.Salt = "солёныйсолёный12";
        });

        var second = Helper.Cipher(options =>
        {
            Helper.Defaults(options);
            options.Salt = "другойдругойдр12";
        });

        Assert.ThrowsAny<CryptographicException>(() => second.Decrypt(first.Encrypt([7])));
    }
}
