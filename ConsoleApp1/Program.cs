using System.Threading.Tasks;
using System;
using System.IO;
using System.Text;
using Enigma.BlockCiphers;
using Enigma.Padding;
using Enigma.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ConsoleApp1;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        await Task.CompletedTask;

        try
        {
            // Create a cipher with PKCS7 padding (default)
            var paddedCipher = new PaddedBufferedBlockCipher(
                new EcbBlockCipher(new AesEngine())
            );

            // Or specify a different padding scheme explicitly
            var paddedCipher2 = new PaddedBufferedBlockCipher(new EcbBlockCipher(new AesEngine()), new Pkcs7Padding());
            
            var test = new BufferedBlockCipher(new EcbBlockCipher(new AesEngine()));
            
            // Create a block cipher service for AES-CBC
            var engineFactory = new BlockCipherEngineFactory();
            // var service = new BlockCipherServiceFactory().CreateCbcBlockCipherService(engineFactory.CreateAesEngine);

            // var service = new BlockCipherService(() => CipherUtilities.GetCipher("AES/CBC/NoPadding"));
            var service = new BlockCipherService("AES/CBC/PKCS7Padding");

            // Get the key and IV sizes
            var (keySizeInBytes, ivSizeInBytes) = service.GetKeyIvSize();

            // Generate random key and iv
            var key = RandomUtils.GenerateRandomBytes(keySizeInBytes);
            var iv = RandomUtils.GenerateRandomBytes(ivSizeInBytes);
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var data = Encoding.UTF8.GetBytes("This is a secret message !");

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