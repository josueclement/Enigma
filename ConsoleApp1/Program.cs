using System.Threading.Tasks;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Enigma.DataEncoding;
using Enigma.KDF;
using Enigma.PQC;
using Enigma.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace ConsoleApp1;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        await Task.CompletedTask;

        try
        {
            var salt = new Base64Service().Decode(
                "a2ac25560124e9764ecae54368d9c169"); //RandomUtils.GenerateRandomBytes(Argon2SaltSize);
            var passwordData = "test1234"u8.ToArray();

            var service = new Argon2Service();
            var key = service.GenerateKey(64, passwordData, salt);

            await Task.Delay(5000);
            Console.WriteLine("done");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}