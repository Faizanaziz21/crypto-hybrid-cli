using System.Security.Cryptography;
using CryptoHybrid.Core;

return Cli.Run(args);

static class Cli
{
    private const string Usage = """
        Usage:
          crypto-hybrid keygen [--out-dir <dir>] [--bits <n>]
              Writes public.pem and private.pem (RSA, default 3072 bits).
          crypto-hybrid encrypt <in> <out> <pubkey.pem>
          crypto-hybrid decrypt <in> <out> <privkey.pem>
        """;

    public static int Run(string[] args)
    {
        try
        {
            return args.FirstOrDefault() switch
            {
                "keygen" => Keygen(args[1..]),
                "encrypt" when args.Length == 4 => Encrypt(args[1], args[2], args[3]),
                "decrypt" when args.Length == 4 => Decrypt(args[1], args[2], args[3]),
                "-h" or "--help" or "help" => PrintUsage(0),
                _ => PrintUsage(1),
            };
        }
        catch (CryptographicException e)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return 2;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return 1;
        }
    }

    private static int PrintUsage(int code)
    {
        (code == 0 ? Console.Out : Console.Error).WriteLine(Usage);
        return code;
    }

    private static int Keygen(string[] args)
    {
        var outDir = ".";
        var bits = HybridCrypto.DefaultRsaKeySizeBits;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out-dir" when i + 1 < args.Length:
                    outDir = args[++i];
                    break;
                case "--bits" when i + 1 < args.Length && int.TryParse(args[i + 1], out var b):
                    bits = b;
                    i++;
                    break;
                default:
                    return PrintUsage(1);
            }
        }

        Directory.CreateDirectory(outDir);
        var publicPath = Path.Combine(outDir, "public.pem");
        var privatePath = Path.Combine(outDir, "private.pem");
        var (publicPem, privatePem) = HybridCrypto.GenerateKeyPair(bits);

        File.WriteAllText(publicPath, publicPem);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(privatePath, privatePem);
        }
        else
        {
            // Create the private key owner-read/write only from the start.
            using var fs = new FileStream(privatePath, new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            using var writer = new StreamWriter(fs);
            writer.Write(privatePem);
        }

        Console.WriteLine($"Wrote {publicPath} and {privatePath} ({bits}-bit RSA).");
        return 0;
    }

    private static int Encrypt(string input, string output, string publicKeyPath)
    {
        var container = HybridCrypto.Encrypt(File.ReadAllBytes(input), File.ReadAllText(publicKeyPath));
        File.WriteAllBytes(output, container);
        Console.WriteLine($"Encrypted {input} -> {output}");
        return 0;
    }

    private static int Decrypt(string input, string output, string privateKeyPath)
    {
        // Decrypt fully in memory first so nothing is written unless authentication succeeds.
        var plaintext = HybridCrypto.Decrypt(File.ReadAllBytes(input), File.ReadAllText(privateKeyPath));
        File.WriteAllBytes(output, plaintext);
        Console.WriteLine($"Decrypted {input} -> {output}");
        return 0;
    }
}
