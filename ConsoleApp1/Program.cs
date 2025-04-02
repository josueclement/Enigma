using System.Threading.Tasks;
using System;
using Enigma.PQC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

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

            var keyPair = service.GenerateKeyPair();
                
            // Sign/verify data
            var signature = service.Sign(data, keyPair.Private);
            var verified = service.Verify(data, signature, keyPair.Public);


            // var data = "This is a message to sign and verify"u8.ToArray();
            //
            // //var test = NistObjectIdentifiers.id_hash_ml_dsa_87_with_sha512
            //
            // var random = new SecureRandom();
            // // Generate ML-DSA key pair.
            // var kpg = new MLDsaKeyPairGenerator();
            // kpg.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
            // var kp = kpg.GenerateKeyPair();
            // // Create ML-DSA signer.
            // var signer = SignerUtilities.InitSigner("ML-DSA-65", forSigning: true, kp.Private, random);
            // // Generate ML-DSA signature.
            // signer.BlockUpdate(data, 0, data.Length);
            // byte[] signature = signer.GenerateSignature();
            // // Verify ML-DSA signature.
            // var verifier = SignerUtilities.InitSigner("ML-DSA-65", forSigning: false, kp.Public, random: null);
            // verifier.BlockUpdate(data, 0, data.Length);
            // if (verifier.VerifySignature(signature))
            // {
            //     Console.WriteLine("ML-DSA-65 signature created and verified successfully");
            // }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}