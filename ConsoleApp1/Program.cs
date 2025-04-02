using System.Threading.Tasks;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
            // var service = new ModuleLatticeBasedDsaServiceFactory().CreateMlDsa65Service();
            //
            // var kp = service.GenerateKeyPair();
            //
            // using var pubOutput = new MemoryStream();
            // PemUtils.SaveKey(kp.Public, pubOutput);
            // var pub = pubOutput.ToArray();
            //
            // using var priOutput = new MemoryStream();
            // // PemUtils.SavePrivateKey(kp.Private, priOutput, "test1234");
            // PemUtils.SaveKey(kp.Private, priOutput);
            // var pri = priOutput.ToArray();
            //
            // using var pubInput = new MemoryStream(pub);
            // var pubRead = PemUtils.LoadKey(pubInput);
            //
            // using var priInput = new MemoryStream(pri);
            // var priRead = PemUtils.LoadKey(priInput);

            var random = new SecureRandom();
            // Generate ML-KEM-512 key pair.
            var kpg = new MLKemKeyPairGenerator();
            kpg.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_1024));
            var kp = kpg.GenerateKeyPair();
            
            // Generate an encapsulation to the public key and store the secret.
            var encapsulator = KemUtilities.GetEncapsulator("ML-KEM-1024");
            encapsulator.Init(kp.Public);
            byte[] encapsulation = new byte[encapsulator.EncapsulationLength];
            byte[] encapSecret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(encapsulation, 0, encapsulation.Length, encapSecret, 0, encapSecret.Length);
            
            // Extract the secret using the private key.
            var decapsulator = KemUtilities.GetDecapsulator("ML-KEM-1024");
            decapsulator.Init(kp.Private);
            byte[] decapSecret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(encapsulation, 0, encapsulation.Length, decapSecret, 0, decapSecret.Length);
            
            // Check we got the same secret on both sides.
            if (Arrays.AreEqual(encapSecret, decapSecret))
            {
                Console.WriteLine("Shared secret generated successfully: " + Hex.ToHexString(encapSecret));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
    
    // --- Configuration ---
    // Argon2 Parameters (Adjust based on security needs and performance constraints)
    private const int Argon2Iterations = 10;        // Time cost
    private const int Argon2MemoryKiB = 65536;      // 64 MiB memory cost
    private const int Argon2Parallelism = 4;        // Degree of parallelism
    private const int Argon2SaltSize = 16;          // Bytes for Salt
    private const int Argon2KeySize = 32;           // Bytes for derived key (AES-256)

    // AES-GCM Parameters
    private const int GcmNonceSize = 12;            // Bytes for Nonce (IV) - 12 bytes is recommended for GCM
    private const int GcmTagSize = 16;              // Bytes (128 bits) for Authentication Tag

    private static readonly SecureRandom _secureRandom = new SecureRandom();
    
    /// <summary>
    /// Encrypts plaintext using a password, deriving the key with Argon2id and encrypting with AES-GCM.
    /// </summary>
    /// <param name="password">The password to use for key derivation.</param>
    /// <param name="plainText">The data to encrypt.</param>
    /// <returns>A byte array containing Salt + Nonce + CiphertextWithAuthTag, or null on error.</returns>
    public static byte[] EncryptWithArgon2(string password, byte[] plainText)
    {
        if (string.IsNullOrEmpty(password) || plainText == null)
        {
            throw new ArgumentNullException("Password and plaintext cannot be null or empty.");
        }

        try
        {
            // 1. Generate Salt
            byte[] salt = new byte[Argon2SaltSize];
            _secureRandom.NextBytes(salt);

            // 2. Derive Key using Argon2id
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            // var argon2Params = new Argon2Parameters.Builder(Argon2Parameters.Argon2_id) // AI ERROR
            var argon2Params = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                // .WithVersion(Argon2Parameters.Argon2_version_13) // Use Argon2 version 1.3 // AI ERROR
                .WithVersion(Argon2Parameters.Version13) // Use Argon2 version 1.3
                .WithIterations(Argon2Iterations)
                .WithMemoryPowOfTwo(16) // Translates KiB for BC. 65536 KiB = 2^16
                // .WithMemoryAsKB(Argon2MemoryKiB) // Alternative if WithMemoryPowOfTwo is confusing
                .WithParallelism(Argon2Parallelism)
                .WithSalt(salt)
                .Build();

            var argon2Gen = new Argon2BytesGenerator();
            argon2Gen.Init(argon2Params);

            byte[] derivedKey = new byte[Argon2KeySize];
            // Note: BC generator takes output buffer, offset, length
            argon2Gen.GenerateBytes(passwordBytes, derivedKey, 0, derivedKey.Length);

            // Clean up password bytes immediately
            Array.Clear(passwordBytes, 0, passwordBytes.Length);

            // 3. Generate Nonce (IV)
            byte[] nonce = new byte[GcmNonceSize];
            _secureRandom.NextBytes(nonce);

            // 4. Encrypt using AES-GCM
            var cipher = new GcmBlockCipher(new AesEngine());
            var keyParam = new KeyParameter(derivedKey);
            // AEAD parameters: key, macSize (bits), nonce, associatedData (optional, null here)
            var aeadParams = new AeadParameters(keyParam, GcmTagSize * 8, nonce, null);
            cipher.Init(true, aeadParams); // true = encrypt

            byte[] cipherTextWithTag = new byte[cipher.GetOutputSize(plainText.Length)];
            int len = cipher.ProcessBytes(plainText, 0, plainText.Length, cipherTextWithTag, 0);
            cipher.DoFinal(cipherTextWithTag, len); // Completes encryption and appends auth tag

            // 5. Combine Salt, Nonce, and Ciphertext+Tag for storage/transmission
            byte[] result = new byte[salt.Length + nonce.Length + cipherTextWithTag.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
            Buffer.BlockCopy(cipherTextWithTag, 0, result, salt.Length + nonce.Length, cipherTextWithTag.Length);

            // Clean up derived key
            Array.Clear(derivedKey, 0, derivedKey.Length);

            return result;
        }
        catch (Exception ex) // Catch BouncyCastle specific exceptions if needed
        {
            Console.Error.WriteLine($"Encryption failed: {ex.Message}");
            // Consider logging the full exception details
            // Rethrow or return null/handle error as appropriate for your application
            throw; // Rethrowing for clarity in example
        }
    }

    /// <summary>
    /// Decrypts data previously encrypted with EncryptWithArgon2.
    /// </summary>
    /// <param name="password">The password used during encryption.</param>
    /// <param name="encryptedDataWithSaltAndNonce">The combined Salt + Nonce + CiphertextWithAuthTag.</param>
    /// <returns>The original plaintext byte array, or null/throws if decryption fails.</returns>
    public static byte[] DecryptWithArgon2(string password, byte[] encryptedDataWithSaltAndNonce)
    {
        if (string.IsNullOrEmpty(password) || encryptedDataWithSaltAndNonce == null ||
            encryptedDataWithSaltAndNonce.Length < Argon2SaltSize + GcmNonceSize + GcmTagSize) // Basic check
        {
            throw new ArgumentException("Invalid input for decryption.");
        }

        try
        {
            // 1. Extract Salt, Nonce, and Ciphertext+Tag
            byte[] salt = new byte[Argon2SaltSize];
            Buffer.BlockCopy(encryptedDataWithSaltAndNonce, 0, salt, 0, salt.Length);

            byte[] nonce = new byte[GcmNonceSize];
            Buffer.BlockCopy(encryptedDataWithSaltAndNonce, salt.Length, nonce, 0, nonce.Length);

            int cipherTextLength = encryptedDataWithSaltAndNonce.Length - salt.Length - nonce.Length;
            byte[] cipherTextWithTag = new byte[cipherTextLength];
            Buffer.BlockCopy(encryptedDataWithSaltAndNonce, salt.Length + nonce.Length, cipherTextWithTag, 0, cipherTextLength);

            // 2. Re-Derive Key using Argon2id (MUST use the *same* salt and parameters)
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            var argon2Params = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithIterations(Argon2Iterations)
                .WithMemoryPowOfTwo(16)
                // .WithMemoryAsKB(Argon2MemoryKiB)
                .WithParallelism(Argon2Parallelism)
                .WithSalt(salt) // Use the extracted salt
                .Build();

            var argon2Gen = new Argon2BytesGenerator();
            argon2Gen.Init(argon2Params);

            byte[] derivedKey = new byte[Argon2KeySize];
            argon2Gen.GenerateBytes(passwordBytes, derivedKey, 0, derivedKey.Length);

            // Clean up password bytes immediately
            Array.Clear(passwordBytes, 0, passwordBytes.Length);

            // 3. Decrypt using AES-GCM
            var cipher = new GcmBlockCipher(new AesEngine());
            var keyParam = new KeyParameter(derivedKey);
            // Use the extracted nonce
            var aeadParams = new AeadParameters(keyParam, GcmTagSize * 8, nonce, null);
            cipher.Init(false, aeadParams); // false = decrypt

            byte[] plainText = new byte[cipher.GetOutputSize(cipherTextWithTag.Length)];
            int len = cipher.ProcessBytes(cipherTextWithTag, 0, cipherTextWithTag.Length, plainText, 0);

            // **Crucial:** DoFinal performs the authentication tag check.
            // It will throw an InvalidCipherTextException if the tag is invalid (tampered data or wrong key/password).
            cipher.DoFinal(plainText, len);

            // Clean up derived key
            Array.Clear(derivedKey, 0, derivedKey.Length);

            // Trim plaintext if needed (GCM GetOutputSize might overestimate slightly, DoFinal tells actual length implicitly)
            // In many cases with BC GCM, the initial buffer size is exact, but check if needed.
            // If DoFinal succeeded without throwing, decryption and authentication were successful.

            // We might need to resize plainText based on the actual output length.
            // However, often with GCM the buffer size from GetOutputSize is correct.
            // If you encounter issues with extra null bytes, you might need:
            // Array.Resize(ref plainText, len + cipher.GetUpdateOutputSize(0)); // Example, adapt as needed


            return plainText;
        }
        catch (InvalidCipherTextException ex)
        {
            // This specifically indicates decryption failure due to bad password or tampered data
            Console.Error.WriteLine($"Decryption failed (likely wrong password or data corrupted): {ex.Message}");
            throw new CryptographicException("Decryption failed. Password may be incorrect or data tampered.", ex);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Decryption failed: {ex.Message}");
            // Log details
            throw; // Rethrow
        }
    }

    // --- Main Method for Demonstration ---
    public static void Main2(string[] args)
    {
        string myPassword = "VerySecretPassword123!";
        string mySensitiveData = "This is highly confidential data.";
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(mySensitiveData);

        Console.WriteLine($"Original: {mySensitiveData}");

        try
        {
            // Encrypt
            byte[] encryptedBlob = EncryptWithArgon2(myPassword, plainTextBytes);
            Console.WriteLine($"Encrypted (Base64): {Convert.ToBase64String(encryptedBlob)}");
            Console.WriteLine($"Encrypted blob length: {encryptedBlob.Length} bytes");

            // Decrypt (Correct Password)
            byte[] decryptedBytes = DecryptWithArgon2(myPassword, encryptedBlob);
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Decrypted: {decryptedText}");

            // Verify
            if (mySensitiveData == decryptedText)
            {
                Console.WriteLine("SUCCESS: Decrypted data matches original.");
            }
            else
            {
                Console.WriteLine("ERROR: Decrypted data does NOT match original.");
            }

            // Decrypt (Incorrect Password) - Demonstration of failure
            Console.WriteLine("\nAttempting decryption with WRONG password:");
            try
            {
                DecryptWithArgon2("WrongPassword!", encryptedBlob);
            }
            catch (CryptographicException ex) // Catching the specific rethrown exception
            {
                Console.WriteLine($"Expected decryption failure: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected exception during wrong password test: {ex.GetType().Name} - {ex.Message}");
            }

        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }
}