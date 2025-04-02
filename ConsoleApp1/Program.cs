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
    
    // Standard Nonce size for GCM: 12 bytes / 96 bits
    private const int NonceBitSize = 96;
    private const int NonceSizeInBytes = NonceBitSize / 8;

    // Standard Tag size for GCM: 16 bytes / 128 bits
    private const int MacBitSize = 128;

    private static readonly SecureRandom Random = new SecureRandom();

    // Generates a cryptographically secure random nonce
    public static byte[] GenerateNonce()
    {
        byte[] nonce = new byte[NonceSizeInBytes];
        Random.NextBytes(nonce);
        return nonce;

        // Alternative using .NET's built-in RNG
        // return RandomNumberGenerator.GetBytes(NonceSizeInBytes);
    }

    public static byte[] Encrypt(byte[] plainText, byte[] key, byte[] nonce, byte[] associatedData = null)
    {
        if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
        {
            throw new ArgumentException("Key must be 128, 192, or 256 bits.", nameof(key));
        }
        if (nonce == null || nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentException($"Nonce must be {NonceSizeInBytes} bytes.", nameof(nonce));
        }

        // Use AES as the underlying block cipher
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, associatedData);

        // Initialize cipher for encryption (true)
        cipher.Init(true, parameters);

        // Calculate output buffer size
        int cipherTextLength = cipher.GetOutputSize(plainText.Length);
        byte[] cipherTextWithTag = new byte[cipherTextLength];

        // Process plaintext
        int len = cipher.ProcessBytes(plainText, 0, plainText.Length, cipherTextWithTag, 0);

        // Finalize encryption (computes & appends tag)
        try
        {
            cipher.DoFinal(cipherTextWithTag, len);
        }
        catch (InvalidCipherTextException e)
        {
            // Should not happen during encryption normally
            Console.WriteLine($"Error during GCM encryption: {e.Message}");
            throw;
        }

        // The output buffer `cipherTextWithTag` now contains: [ Ciphertext | Tag ]
        return cipherTextWithTag;
    }

    public static byte[] Decrypt(byte[] cipherTextWithTag, byte[] key, byte[] nonce, byte[] associatedData = null)
    {
         if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
        {
            throw new ArgumentException("Key must be 128, 192, or 256 bits.", nameof(key));
        }
        if (nonce == null || nonce.Length != NonceSizeInBytes)
        {
            throw new ArgumentException($"Nonce must be {NonceSizeInBytes} bytes.", nameof(nonce));
        }
        // Ciphertext must be at least as long as the tag
        if (cipherTextWithTag == null || cipherTextWithTag.Length < (MacBitSize / 8))
        {
             throw new ArgumentException($"Ciphertext is too short to contain a tag.", nameof(cipherTextWithTag));
        }

        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, associatedData);

        // Initialize cipher for decryption (false)
        cipher.Init(false, parameters);

        // Calculate output buffer size (will be plaintext size)
        int plainTextLength = cipher.GetOutputSize(cipherTextWithTag.Length);
        byte[] plainText = new byte[plainTextLength];

        // Process ciphertext + tag
        int len = cipher.ProcessBytes(cipherTextWithTag, 0, cipherTextWithTag.Length, plainText, 0);

        try
        {
            // Finalize decryption (verifies the tag).
            // Throws InvalidCipherTextException if tag verification fails!
            cipher.DoFinal(plainText, len);

            // If DoFinal doesn't throw, decryption & verification succeeded.
            // The plaintext buffer contains the original data.
            return plainText;
        }
        catch (InvalidCipherTextException e)
        {
            // TAG VERIFICATION FAILED! The data is corrupt or tampered with.
            Console.WriteLine($"GCM Decryption failed: Tag mismatch or invalid ciphertext. {e.Message}");
            // --- CRITICAL: DO NOT USE THE PARTIALLY DECRYPTED DATA IN `plainText` ---
            // Return null or throw a custom exception to indicate failure.
            return null;
        }
    }

    // --- Example Usage ---
    public static void Main2(string[] args)
    {
        // 1. Generate a secure key (e.g., AES-256 requires a 32-byte key)
        // In a real app, derive this securely (e.g., using a KDF) or load it safely.
        // For demo purposes, we generate one randomly. Keep this key SECRET.
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        Console.WriteLine($"Using Key: {Convert.ToHexString(key)}");

        // 2. Prepare Plaintext and Associated Data
        string plainTextString = "This is a highly secret message!";
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainTextString);
        Console.WriteLine($"Original Plaintext: '{plainTextString}'");

        string associatedDataString = "Sender=Alice,Recipient=Bob,SessionID=12345";
        byte[] associatedDataBytes = Encoding.UTF8.GetBytes(associatedDataString);
        Console.WriteLine($"Associated Data: '{associatedDataString}'");

        // --- Encryption ---
        // 3. Generate a UNIQUE Nonce for this specific encryption operation
        byte[] nonce = GenerateNonce();
        Console.WriteLine($"Using Nonce: {Convert.ToHexString(nonce)}");

        // 4. Encrypt
        byte[] cipherTextWithTag = Encrypt(plainTextBytes, key, nonce, associatedDataBytes);
        Console.WriteLine($"Ciphertext + Tag: {Convert.ToHexString(cipherTextWithTag)}");
        Console.WriteLine($"Ciphertext + Tag length: {cipherTextWithTag.Length} bytes"); // plaintext length + tag length

        // --- Decryption (Successful Case) ---
        Console.WriteLine("\n--- Attempting Decryption (Success Case) ---");
        byte[] decryptedBytes = Decrypt(cipherTextWithTag, key, nonce, associatedDataBytes);

        if (decryptedBytes != null)
        {
            string decryptedString = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Decryption Successful!");
            Console.WriteLine($"Decrypted Plaintext: '{decryptedString}'");
            Console.WriteLine($"Verification Check: {(plainTextString == decryptedString ? "PASSED" : "FAILED")}");
        }
        else
        {
             Console.WriteLine("Decryption FAILED verification.");
        }


        // --- Decryption (Tampered Data Case) ---
        Console.WriteLine("\n--- Attempting Decryption (Tampered Ciphertext Case) ---");
        byte[] tamperedCipherText = (byte[])cipherTextWithTag.Clone();
        // Flip a bit in the ciphertext part (before the tag)
        if (tamperedCipherText.Length > 1)
        {
             tamperedCipherText[0] ^= 0x01; // Flip the first bit of the first byte
        }
        Console.WriteLine($"Tampered Ciphertext + Tag: {Convert.ToHexString(tamperedCipherText)}");

        byte[] tamperedResult = Decrypt(tamperedCipherText, key, nonce, associatedDataBytes);
        if (tamperedResult == null)
        {
             Console.WriteLine("Decryption correctly FAILED due to tampered ciphertext (tag mismatch).");
        }
        else
        {
            Console.WriteLine("!!! SECURITY ALERT: Decryption SUCCEEDED despite tampered ciphertext !!!");
        }


        // --- Decryption (Tampered AAD Case) ---
        Console.WriteLine("\n--- Attempting Decryption (Tampered Associated Data Case) ---");
        byte[] tamperedAssociatedData = Encoding.UTF8.GetBytes("Sender=Eve,Recipient=Bob,SessionID=67890"); // Different AAD
        Console.WriteLine($"Original Associated Data: '{associatedDataString}'");
        Console.WriteLine($"Tampered Associated Data: '{Encoding.UTF8.GetString(tamperedAssociatedData)}'");

        byte[] tamperedAadResult = Decrypt(cipherTextWithTag, key, nonce, tamperedAssociatedData); // Use original ciphertext, but wrong AAD
         if (tamperedAadResult == null)
        {
             Console.WriteLine("Decryption correctly FAILED due to tampered associated data (tag mismatch).");
        }
        else
        {
            Console.WriteLine("!!! SECURITY ALERT: Decryption SUCCEEDED despite tampered AAD !!!");
        }

        // --- Decryption (Wrong Nonce Case) ---
        Console.WriteLine("\n--- Attempting Decryption (Wrong Nonce Case) ---");
        byte[] wrongNonce = GenerateNonce(); // Generate a different nonce
        Console.WriteLine($"Original Nonce: {Convert.ToHexString(nonce)}");
        Console.WriteLine($"Wrong Nonce:    {Convert.ToHexString(wrongNonce)}");

        byte[] wrongNonceResult = Decrypt(cipherTextWithTag, key, wrongNonce, associatedDataBytes); // Use original ciphertext, but wrong Nonce
         if (wrongNonceResult == null)
        {
             Console.WriteLine("Decryption correctly FAILED due to wrong nonce (tag mismatch / garbled data).");
         }
        else
        {
            // Depending on implementation, wrong nonce might just produce garbage OR fail tag check.
            // GCM's tag depends on the Nonce, so this should fail the tag check.
            Console.WriteLine($"Decryption with wrong nonce produced: '{Encoding.UTF8.GetString(wrongNonceResult)}' (EXPECTED FAILURE)");
        }
    }
}