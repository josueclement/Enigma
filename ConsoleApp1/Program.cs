using System.Threading.Tasks;
using System;
using System.IO;
using System.Text;
using Enigma.PQC;
using Enigma.Extensions;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace ConsoleApp1;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        await Task.CompletedTask;

        try
        {
            var data = "This is a message to sign and verify"u8.ToArray();

            var service = new ModuleLatticeBasedDsaServiceFactory().CreateMlDsa87Service();

            await using var inputPublic = new FileStream(@"C:\Temp\mldsa_public.pem", FileMode.Open, FileAccess.Read);
            var publicKey = service.LoadKey(inputPublic);
            await using var inputPrivate = new FileStream(@"C:\Temp\mldsa_private.pem", FileMode.Open, FileAccess.Read);
            var privateKey = service.LoadPrivateKey(inputPrivate, "test1234");
                
            // Sign/verify data
            var signature = service.Sign(data, privateKey);
            var verified = service.Verify(data, signature, publicKey);


            // var data = "This is a message to sign and verify"u8.ToArray();
            //
            // var service = new ModuleLatticeBasedDsaServiceFactory().CreateMlDsa87Service();
            //
            // var keyPair = service.GenerateKeyPair();
            //     
            // // Sign/verify data
            // var signature = service.Sign(data, keyPair.Private);
            // var verified = service.Verify(data, signature, keyPair.Public);
            //
            // await using var output = new FileStream(@"C:\Temp\mldsa_public.pem", FileMode.Create, FileAccess.Write);
            // await using var writer = new StreamWriter(output, Encoding.UTF8);
            // var pemWriter = new PemWriter(writer);
            // pemWriter.WriteObject(keyPair.Public);
            //
            // await using var outputPrivate = new FileStream(@"C:\Temp\mldsa_private.pem", FileMode.Create, FileAccess.Write);
            // await using var writerPrivate = new StreamWriter(outputPrivate, Encoding.UTF8);
            // var pemWriterPrivate = new PemWriter(writerPrivate);
            // pemWriterPrivate.WriteObject(keyPair.Private, "AES-256-CBC", "test1234".ToCharArray(), new SecureRandom());
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}