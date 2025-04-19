using Enigma.BlockCiphers;
using Enigma.DataEncoding;
using Enigma.Extensions;
using Enigma.Hash;
using Enigma.KDF;
using Enigma.PQC;
using Enigma.Padding;
using Enigma.PublicKey;
using Enigma.StreamCiphers;
using Enigma.Utils;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;

namespace ConsoleApp1;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        await Task.CompletedTask;

        try
        {
            // Create block cipher service
            var service = new BlockCipherService("AES/GCM");

            // Generate random key and nonce
            var key = RandomUtils.GenerateRandomBytes(32);
            var nonce = RandomUtils.GenerateRandomBytes(12);
            var parameters = new BlockCipherParametersFactory().CreateGcmParameters(key, nonce, "associated data".GetUtf8Bytes());

            var data = "This is a secret message !".GetUtf8Bytes();

            // Encrypt
            using var inputEnc = new MemoryStream(data);
            using var outputEnc = new MemoryStream();
            await service.EncryptAsync(inputEnc, outputEnc, parameters);

            var encrypted = outputEnc.ToArray();

            // Decrypt
            using var inputDec = new MemoryStream(encrypted);
            using var outputDec = new MemoryStream();
            await service.DecryptAsync(inputDec, outputDec, parameters);

            var decrypted = outputDec.ToArray();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}