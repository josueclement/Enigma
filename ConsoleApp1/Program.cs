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
            // KDF = ARGON2ID
            // Ctrl.lanes = lanes:4
            // Ctrl.iter = iter:3
            // Ctrl.memcost = memcost:32
            // Ctrl.pass = hexpass:0101010101010101010101010101010101010101010101010101010101010101
            // Ctrl.salt = hexsalt:02020202020202020202020202020202
            // Output = 03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e
            
            
            
            var service = new Argon2Service();
            var key = service.GenerateKey(
                size: 32,
                passwordBytes: "".FromHexString(),
                salt: "02020202020202020202020202020202".FromHexString(),
                iterations: 3,
                parallelism: 4,
                memoryPowOfTwo: 5);
            var res = key.ToHexString();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}