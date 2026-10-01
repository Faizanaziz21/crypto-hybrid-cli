# crypto-hybrid-cli

A small C#/.NET 8 command-line tool for hybrid file encryption: each file gets a fresh
AES-256-GCM key, and that key is wrapped with the recipient's RSA public key (RSA-OAEP, SHA-256).
Only the holder of the matching private key can decrypt, and any modification to the encrypted
file is detected before any plaintext is written.

## Usage

```sh
# Generate an RSA keypair (default 3072-bit) -> public.pem (SPKI) + private.pem (PKCS#8, mode 0600)
crypto-hybrid keygen [--out-dir <dir>] [--bits <n>]

# Encrypt for the owner of public.pem
crypto-hybrid encrypt <in> <out> <public.pem>

# Decrypt with private.pem; fails if the key is wrong or the file was tampered with
crypto-hybrid decrypt <in> <out> <private.pem>
```

Exit codes: `0` success, `1` usage or I/O error, `2` cryptographic failure
(wrong key, tampering, corrupt input).

Example:

```sh
crypto-hybrid keygen --out-dir keys
crypto-hybrid encrypt report.pdf report.pdf.enc keys/public.pem
crypto-hybrid decrypt report.pdf.enc report.pdf keys/private.pem
```

## Encrypted file format

All integers big-endian.

| Field        | Size        | Description                                  |
|--------------|-------------|----------------------------------------------|
| magic        | 4           | `HYB1`                                       |
| keyLen       | 2           | length of the wrapped key (RSA modulus bytes)|
| wrappedKey   | keyLen      | RSA-OAEP-SHA256(AES key)                     |
| nonce        | 12          | random AES-GCM nonce                         |
| tag          | 16          | AES-GCM authentication tag                   |
| ciphertext   | rest        | AES-256-GCM(plaintext)                       |

The header (magic, keyLen, wrappedKey, nonce) is passed to GCM as associated data, so flipping
any bit in the header, tag, or ciphertext makes decryption fail.

## Threat model

**Protects against**

- *Confidentiality:* an attacker who obtains the encrypted file but not the private key learns
  nothing about the contents beyond their length.
- *Integrity:* any modification of the encrypted file (ciphertext, tag, nonce, wrapped key, or
  header) is detected by the GCM tag; decryption aborts and no output file is written.
- *Wrong key:* decrypting with a different private key fails cleanly instead of producing garbage.

**Does not protect against**

- *Sender authentication:* anyone with the public key can create a valid encrypted file. This is
  encryption, not a signature: a successful decrypt proves the file wasn't altered after
  encryption, not who encrypted it. Sign separately if origin matters.
- *Private key compromise:* the private key PEM is stored unencrypted (file mode 0600 on Unix).
  Protect it with filesystem permissions or disk encryption; there is no passphrase support.
- *Public key substitution:* verify that the public key you encrypt to really belongs to the
  recipient (out of band).
- *Metadata:* file size, file name, and timestamps are not hidden.
- *Compromised host:* malware on the machine doing encryption or decryption can read plaintext
  and keys.

**Limits:** files are processed in memory, so the practical maximum is bounded by available RAM
(and by .NET's ~2 GB array limit).

## Build and run

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download).

```sh
dotnet build
dotnet test

# Run without installing
dotnet run --project src/CryptoHybrid.Cli -- keygen --out-dir keys

# Or publish a standalone binary
dotnet publish src/CryptoHybrid.Cli -c Release -o out
./out/crypto-hybrid --help
```

## Project layout

- `src/CryptoHybrid.Core` – encryption/decryption and key generation (`HybridCrypto`).
- `src/CryptoHybrid.Cli` – the `crypto-hybrid` command-line front end.
- `tests/CryptoHybrid.Tests` – xUnit tests: round-trip, wrong-key rejection, tamper detection.
