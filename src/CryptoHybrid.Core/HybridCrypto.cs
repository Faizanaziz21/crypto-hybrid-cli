using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoHybrid.Core;

/// <summary>
/// Hybrid encryption: a fresh random AES-256-GCM key encrypts the payload, and that key is
/// wrapped with RSA-OAEP (SHA-256) under the recipient's public key.
/// </summary>
/// <remarks>
/// Container layout (all integers big-endian):
/// <code>
/// magic      4 bytes   "HYB1"
/// keyLen     2 bytes   length of the wrapped key (= RSA modulus size in bytes)
/// wrappedKey keyLen    RSA-OAEP-SHA256(aesKey)
/// nonce      12 bytes  AES-GCM nonce
/// tag        16 bytes  AES-GCM authentication tag
/// ciphertext rest      AES-256-GCM(plaintext)
/// </code>
/// Everything before the tag (magic, keyLen, wrappedKey, nonce) is bound to the ciphertext as
/// GCM associated data, so any modification to the header or body fails authentication.
/// </remarks>
public static class HybridCrypto
{
    public const int AesKeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int DefaultRsaKeySizeBits = 3072;

    private static readonly byte[] Magic = "HYB1"u8.ToArray();
    private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

    public static (string PublicPem, string PrivatePem) GenerateKeyPair(int keySizeBits = DefaultRsaKeySizeBits)
    {
        if (keySizeBits < 2048)
            throw new ArgumentOutOfRangeException(nameof(keySizeBits), "RSA keys must be at least 2048 bits.");

        using var rsa = RSA.Create(keySizeBits);
        return (rsa.ExportSubjectPublicKeyInfoPem(), rsa.ExportPkcs8PrivateKeyPem());
    }

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);

        var aesKey = RandomNumberGenerator.GetBytes(AesKeySize);
        try
        {
            var wrappedKey = rsa.Encrypt(aesKey, Padding);
            var headerLen = Magic.Length + 2 + wrappedKey.Length + NonceSize;
            var output = new byte[headerLen + TagSize + plaintext.Length];
            var span = output.AsSpan();

            Magic.CopyTo(span);
            BinaryPrimitives.WriteUInt16BigEndian(span[Magic.Length..], checked((ushort)wrappedKey.Length));
            wrappedKey.CopyTo(span[(Magic.Length + 2)..]);
            var nonce = span.Slice(headerLen - NonceSize, NonceSize);
            RandomNumberGenerator.Fill(nonce);

            var header = span[..headerLen];
            var tag = span.Slice(headerLen, TagSize);
            var ciphertext = span[(headerLen + TagSize)..];

            using var aes = new AesGcm(aesKey, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, header);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    /// <exception cref="CryptographicException">
    /// The container is malformed, was encrypted for a different key, or has been tampered with.
    /// </exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> container, string privateKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);

        var minLen = Magic.Length + 2;
        if (container.Length < minLen || !container[..Magic.Length].SequenceEqual(Magic))
            throw new CryptographicException("Input is not a recognised encrypted container.");

        int keyLen = BinaryPrimitives.ReadUInt16BigEndian(container[Magic.Length..]);
        var headerLen = minLen + keyLen + NonceSize;
        if (container.Length < headerLen + TagSize)
            throw new CryptographicException("Encrypted container is truncated.");
        if (keyLen != rsa.KeySize / 8)
            throw new CryptographicException("Decryption failed: wrong private key or corrupted data.");

        var header = container[..headerLen];
        var wrappedKey = container.Slice(minLen, keyLen);
        var nonce = container.Slice(headerLen - NonceSize, NonceSize);
        var tag = container.Slice(headerLen, TagSize);
        var ciphertext = container[(headerLen + TagSize)..];

        byte[] aesKey;
        try
        {
            aesKey = rsa.Decrypt(wrappedKey.ToArray(), Padding);
        }
        catch (CryptographicException e)
        {
            throw new CryptographicException("Decryption failed: wrong private key or corrupted data.", e);
        }

        try
        {
            if (aesKey.Length != AesKeySize)
                throw new CryptographicException("Decryption failed: wrong private key or corrupted data.");

            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(aesKey, TagSize);
            try
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, header);
            }
            catch (AuthenticationTagMismatchException e)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new CryptographicException("Integrity check failed: data has been tampered with or corrupted.", e);
            }
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }
}
