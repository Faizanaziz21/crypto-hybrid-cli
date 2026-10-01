using System.Security.Cryptography;
using System.Text;
using CryptoHybrid.Core;

namespace CryptoHybrid.Tests;

public class HybridCryptoTests
{
    // RSA key generation is slow; share keypairs across tests.
    private static readonly (string Public, string Private) KeyA = HybridCrypto.GenerateKeyPair(2048);
    private static readonly (string Public, string Private) KeyB = HybridCrypto.GenerateKeyPair(2048);

    private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog.");

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(44)]
    [InlineData(1024 * 1024 + 7)]
    public void RoundTrip_RecoversOriginalBytes(int size)
    {
        var data = RandomNumberGenerator.GetBytes(size);

        var container = HybridCrypto.Encrypt(data, KeyA.Public);
        var decrypted = HybridCrypto.Decrypt(container, KeyA.Private);

        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void Encrypt_IsRandomized()
    {
        var c1 = HybridCrypto.Encrypt(Plaintext, KeyA.Public);
        var c2 = HybridCrypto.Encrypt(Plaintext, KeyA.Public);

        Assert.NotEqual(c1, c2);
    }

    [Fact]
    public void Decrypt_WithWrongPrivateKey_Throws()
    {
        var container = HybridCrypto.Encrypt(Plaintext, KeyA.Public);

        Assert.ThrowsAny<CryptographicException>(() => HybridCrypto.Decrypt(container, KeyB.Private));
    }

    [Fact]
    public void Decrypt_WithFlippedCiphertextByte_Throws()
    {
        var container = HybridCrypto.Encrypt(Plaintext, KeyA.Public);
        // Last byte is always ciphertext (non-empty plaintext).
        container[^1] ^= 0x01;

        var ex = Assert.ThrowsAny<CryptographicException>(() => HybridCrypto.Decrypt(container, KeyA.Private));
        Assert.Contains("Integrity check failed", ex.Message);
    }

    [Theory]
    [InlineData("tag")]
    [InlineData("nonce")]
    [InlineData("wrappedKey")]
    [InlineData("magic")]
    public void Decrypt_WithTamperedHeaderOrTag_Throws(string region)
    {
        var container = HybridCrypto.Encrypt(Plaintext, KeyA.Public);
        const int keyLen = 2048 / 8;
        const int headerLen = 4 + 2 + keyLen + HybridCrypto.NonceSize;
        var index = region switch
        {
            "magic" => 0,
            "wrappedKey" => 6 + keyLen / 2,
            "nonce" => headerLen - 1,
            "tag" => headerLen,
            _ => throw new ArgumentOutOfRangeException(nameof(region)),
        };
        container[index] ^= 0x80;

        Assert.ThrowsAny<CryptographicException>(() => HybridCrypto.Decrypt(container, KeyA.Private));
    }

    [Fact]
    public void Decrypt_TruncatedContainer_Throws()
    {
        var container = HybridCrypto.Encrypt(Plaintext, KeyA.Public);

        Assert.ThrowsAny<CryptographicException>(
            () => HybridCrypto.Decrypt(container.AsSpan(0, 20), KeyA.Private));
    }

    [Fact]
    public void GenerateKeyPair_RejectsWeakKeys()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridCrypto.GenerateKeyPair(1024));
    }
}
