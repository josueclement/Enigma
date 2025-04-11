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
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;
using Org.BouncyCastle.Crypto.Modes;

namespace ConsoleApp1;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        await Task.CompletedTask;

        try
        {
            // Create a block cipher service for AES/CBC/PKCS7Padding
            var service = new BlockCipherService("AES/GCM/NoPadding");

            // // Get the key and IV sizes
            // var (keySizeInBytes, ivSizeInBytes) = service.GetKeyIvSize();

            // Generate random key and iv
            var key = RandomUtils.GenerateRandomBytes(32);
            var iv = RandomUtils.GenerateRandomBytes(8);
            var parameters1 = new AeadParameters(new KeyParameter(key), 128, iv, "Hello world !".GetUtf8Bytes());
            var parameters2 = new AeadParameters(new KeyParameter(key), 128, iv, "Hello world !".GetUtf8Bytes());

            var data = "This is a secret message !".GetUtf8Bytes();

            // Encrypt
            using var inputEnc = new MemoryStream(data);
            using var outputEnc = new MemoryStream();
            await service.EncryptAsync(inputEnc, outputEnc, parameters1);

            var encrypted = outputEnc.ToArray();

            // Decrypt
            using var inputDec = new MemoryStream(encrypted);
            using var outputDec = new MemoryStream();
            await service.DecryptAsync(inputDec, outputDec, parameters2);

            var decrypted = outputDec.ToArray();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}