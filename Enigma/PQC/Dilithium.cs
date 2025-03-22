﻿// using Enigma.IO;
// using Enigma.KDF;
// using Enigma.Padding;
// using Enigma.Random;
// using Enigma.SymKey;
// using Org.BouncyCastle.Crypto;
// using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
// using Org.BouncyCastle.Security;
// using System;
// using System.Collections.Generic;
// using System.IO;
// using System.Linq;
//
// namespace Enigma.PQC
// {
//     internal readonly struct DilithiumComponentsSizes
//     {
//         public DilithiumComponentsSizes(int rho, int k, int tr, int s1, int s2, int t0, int t1)
//         {
//             Rho = rho;
//             K = k;
//             Tr = tr;
//             S1 = s1;
//             S2 = s2;
//             T0 = t0;
//             T1 = t1;
//         }
//
//         public int Rho { get; }
//         public int K { get; }
//         public int Tr { get; }
//         public int S1 { get; }
//         public int S2 { get; }
//         public int T0 { get; }
//         public int T1 { get; }
//
//         public static DilithiumComponentsSizes GetComponentsSizes(string type)
//         {
//             switch (type)
//             {
//                 case Dilithium.DILITHIUM2:
//                     return new DilithiumComponentsSizes(32, 32, 64, 384, 384, 1664, 1280);
//                 case Dilithium.DILITHIUM3:
//                     return new DilithiumComponentsSizes(32, 32, 64, 640, 768, 2496, 1920);
//                 case Dilithium.DILITHIUM5:
//                     return new DilithiumComponentsSizes(32, 32, 64, 672, 768, 3328, 2560);
//                 default:
//                     throw new InvalidOperationException();
//             }
//         }
//     }
//
//     /// <summary>
//     /// Dilithium helper class for key pair generation, sign and verify
//     /// </summary>
//     public static class Dilithium
//     {
//         /// <summary>
//         /// <see cref="DilithiumParameters.Dilithium2"/> name
//         /// </summary>
//         public const string DILITHIUM2 = "dilithium2";
//         /// <summary>
//         /// <see cref="DilithiumParameters.Dilithium3"/> name
//         /// </summary>
//         public const string DILITHIUM3 = "dilithium3";
//         /// <summary>
//         /// <see cref="DilithiumParameters.Dilithium5"/> name
//         /// </summary>
//         public const string DILITHIUM5 = "dilithium5";
//
//         /// <summary>
//         /// Generate key pair
//         /// </summary>
//         /// <param name="type">Parameters type</param>
//         /// <param name="publicKey">Public key</param>
//         /// <param name="privateKey">Private key</param>
//         public static void GenerateKeyPair(string type, out DilithiumPublicKeyParameters publicKey, out DilithiumPrivateKeyParameters privateKey)
//         {
//             DilithiumParameters parameters;
//
//             switch (type)
//             {
//                 case DILITHIUM2:
//                     parameters = DilithiumParameters.Dilithium2;
//                     break;
//                 case DILITHIUM3:
//                     parameters = DilithiumParameters.Dilithium3;
//                     break;
//                 case DILITHIUM5:
//                     parameters = DilithiumParameters.Dilithium5;
//                     break;
//                 default:
//                     throw new InvalidOperationException();
//             }
//
//             DilithiumKeyGenerationParameters keyGenParameters = new DilithiumKeyGenerationParameters(new SecureRandom(), parameters);
//             DilithiumKeyPairGenerator dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
//             dilithiumKeyPairGenerator.Init(keyGenParameters);
//             AsymmetricCipherKeyPair keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();
//             publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
//             privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
//         }
//
//         /// <summary>
//         /// Sign data
//         /// </summary>
//         /// <param name="data">Data to sign</param>
//         /// <param name="privateKey">Private key</param>
//         public static byte[] Sign(byte[] data, DilithiumPrivateKeyParameters privateKey)
//         {
//             DilithiumSigner signer = new DilithiumSigner();
//             signer.Init(true, privateKey);
//             return signer.GenerateSignature(data);
//         }
//
//         /// <summary>
//         /// Signature to verify
//         /// </summary>
//         /// <param name="data">Original data</param>
//         /// <param name="signature">Signature</param>
//         /// <param name="publicKey">Public key</param>
//         public static bool Verify(byte[] data, byte[] signature, DilithiumPublicKeyParameters publicKey)
//         {
//             DilithiumSigner signer = new DilithiumSigner();
//             signer.Init(false, publicKey);
//             return signer.VerifySignature(data, signature);
//         }
//
//         #region Save / Load PEM files
//
//         /// <summary>
//         /// Load public key from PEM
//         /// </summary>
//         /// <param name="input">Input stream</param>
//         public static DilithiumPublicKeyParameters LoadPublicKeyFromPEM(Stream input)
//         {
//             PemContent pem = Pem.Read(input);
//             string name = pem.Header.FirstOrDefault(x => x.Name == "Type")?.Value ?? throw new InvalidOperationException();
//             byte[] data = pem.Data ?? throw new InvalidOperationException();
//
//             DilithiumParameters parameters = GetParameters(name);
//             DilithiumComponentsSizes sizes = DilithiumComponentsSizes.GetComponentsSizes(name);
//             byte[] rho = new byte[sizes.Rho];
//             byte[] t1 = new byte[sizes.T1];
//
//             int index = 0;
//             Array.Copy(data, index, rho, 0, sizes.Rho);
//             index += sizes.Rho;
//             Array.Copy(data, index, t1, 0, sizes.T1);
//
//             return new DilithiumPublicKeyParameters(parameters, rho, t1);
//         }
//
//         /// <summary>
//         /// Load public key from PEM file
//         /// </summary>
//         /// <param name="filePath">File path</param>
//         public static DilithiumPublicKeyParameters LoadPublicKeyFromPEM(string filePath)
//         {
//             using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
//             {
//                 return LoadPublicKeyFromPEM(fs);
//             }
//         }
//
//         /// <summary>
//         /// Load private key from PEM
//         /// </summary>
//         /// <param name="input">Input stream</param>
//         public static DilithiumPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input)
//         {
//             PemContent pem = Pem.Read(input);
//             string type = pem.Header.FirstOrDefault(x => x.Name == "Type")?.Value ?? throw new InvalidOperationException();
//             byte[] data = pem.Data ?? throw new InvalidOperationException();
//
//             DilithiumParameters parameters = GetParameters(type);
//             DilithiumComponentsSizes sizes = DilithiumComponentsSizes.GetComponentsSizes(type);
//
//             byte[] rho = new byte[sizes.Rho];
//             byte[] k = new byte[sizes.K];
//             byte[] tr = new byte[sizes.Tr];
//             byte[] s1 = new byte[sizes.S1];
//             byte[] s2 = new byte[sizes.S2];
//             byte[] t0 = new byte[sizes.T0];
//
//             int index = 0;
//             Array.Copy(data, index, rho, 0, sizes.Rho);
//             index += sizes.Rho;
//             Array.Copy(data, index, k, 0, sizes.K);
//             index += sizes.K;
//             Array.Copy(data, index, tr, 0, sizes.Tr);
//             index += sizes.Tr;
//             Array.Copy(data, index, s1, 0, sizes.S1);
//             index += sizes.S1;
//             Array.Copy(data, index, s2, 0, sizes.S2);
//             index += sizes.S2;
//             Array.Copy(data, index, t0, 0, sizes.T0);
//
//             return new DilithiumPrivateKeyParameters(parameters, rho, k, tr, s1, s2, t0, null);
//         }
//
//         /// <summary>
//         /// Load private key from PEM file
//         /// </summary>
//         /// <param name="filePath">File path</param>
//         public static DilithiumPrivateKeyParameters LoadPrivateKeyFromPEM(string filePath)
//         {
//             using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
//             {
//                 return LoadPrivateKeyFromPEM(fs);
//             }
//         }
//
//         /// <summary>
//         /// Load private key from PEM secured with password
//         /// </summary>
//         /// <param name="input">Input stream</param>
//         /// <param name="password">Password</param>
//         public static DilithiumPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input, string password)
//         {
//             PemContent pem = Pem.Read(input);
//             string type = pem.Header.FirstOrDefault(x => x.Name == "Type")?.Value ?? throw new InvalidOperationException();
//             string saltStr = pem.Header.FirstOrDefault(x => x.Name == "Salt")?.Value ?? throw new InvalidOperationException();
//             string ivStr = pem.Header.FirstOrDefault(x => x.Name == "IV")?.Value ?? throw new InvalidOperationException();
//             byte[] enc = pem.Data ?? throw new InvalidOperationException();
//
//             byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, Hex.Decode(saltStr), 600_000);
//             byte[] iv = Hex.Decode(ivStr);
//             byte[] dec = AES.DecryptCBC(enc, key, iv);
//
//             byte[] data = Pkcs7Padding.Instance.Unpad(dec, AES.BLOCK_SIZE);
//
//             DilithiumParameters parameters = GetParameters(type);
//             DilithiumComponentsSizes sizes = DilithiumComponentsSizes.GetComponentsSizes(type);
//
//             byte[] rho = new byte[sizes.Rho];
//             byte[] k = new byte[sizes.K];
//             byte[] tr = new byte[sizes.Tr];
//             byte[] s1 = new byte[sizes.S1];
//             byte[] s2 = new byte[sizes.S2];
//             byte[] t0 = new byte[sizes.T0];
//
//             int index = 0;
//             Array.Copy(data, index, rho, 0, sizes.Rho);
//             index += sizes.Rho;
//             Array.Copy(data, index, k, 0, sizes.K);
//             index += sizes.K;
//             Array.Copy(data, index, tr, 0, sizes.Tr);
//             index += sizes.Tr;
//             Array.Copy(data, index, s1, 0, sizes.S1);
//             index += sizes.S1;
//             Array.Copy(data, index, s2, 0, sizes.S2);
//             index += sizes.S2;
//             Array.Copy(data, index, t0, 0, sizes.T0);
//
//             return new DilithiumPrivateKeyParameters(parameters, rho, k, tr, s1, s2, t0, null);
//         }
//
//         /// <summary>
//         /// Load private key from PEM file secured with password
//         /// </summary>
//         /// <param name="filePath">File path</param>
//         /// <param name="password">Password</param>
//         public static DilithiumPrivateKeyParameters LoadPrivateKeyFromPEM(string filePath, string password)
//         {
//             using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
//             {
//                 return LoadPrivateKeyFromPEM(fs, password);
//             }
//         }
//
//         /// <summary>
//         /// Save public key to PEM
//         /// </summary>
//         /// <param name="publicKey">Public key</param>
//         /// <param name="type">Parameters type</param>
//         /// <param name="output">Output stream</param>
//         public static void SavePublicKeyToPEM(DilithiumPublicKeyParameters publicKey, string type, Stream output)
//         {
//             List<PemHeaderItem> header = new List<PemHeaderItem>
//             {
//                 new PemHeaderItem
//                 {
//                     Name = "Type",
//                     Value = type
//                 }
//             };
//
//             byte[] data = publicKey.GetEncoded();
//             Pem.Write("DILITHIUM PUBLIC KEY", header, data, output);
//         }
//
//         /// <summary>
//         /// Save public key to PEM file
//         /// </summary>
//         /// <param name="publicKey">Public key</param>
//         /// <param name="type">Parameters type</param>
//         /// <param name="filePath">File path</param>
//         public static void SavePublicKeyToPEM(DilithiumPublicKeyParameters publicKey, string type, string filePath)
//         {
//             using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
//             {
//                 SavePublicKeyToPEM(publicKey, type, fs);
//             }
//         }
//
//         /// <summary>
//         /// Save private key to PEM
//         /// </summary>
//         /// <param name="privateKey">Private key</param>
//         /// <param name="type">Parameters type</param>
//         /// <param name="output">Output stream</param>
//         public static void SavePrivateKeyToPEM(DilithiumPrivateKeyParameters privateKey, string type, Stream output)
//         {
//             List<PemHeaderItem> header = new List<PemHeaderItem>
//             {
//                 new PemHeaderItem
//                 {
//                     Name = "Type",
//                     Value = type
//                 }
//             };
//
//             byte[] data = privateKey.GetEncoded();
//             Pem.Write("DILITHIUM PRIVATE KEY", header, data, output);
//             Array.Clear(data, 0, data.Length);
//         }
//
//         /// <summary>
//         /// Save private key to PEM file
//         /// </summary>
//         /// <param name="privateKey">Private key</param>
//         /// <param name="type">Parameters type</param>
//         /// <param name="filePath">File path</param>
//         public static void SavePrivateKeyToPEM(DilithiumPrivateKeyParameters privateKey, string type, string filePath)
//         {
//             using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
//             {
//                 SavePrivateKeyToPEM(privateKey, type, fs);
//             }
//         }
//
//         /// <summary>
//         /// Save private key to PEM secured with a password
//         /// </summary>
//         /// <param name="privateKey">Private key</param>
//         /// <param name="type">Parameters type</param>
//         /// <param name="output">Output stream</param>
//         /// <param name="password">Password</param>
//         public static void SavePrivateKeyToPEM(DilithiumPrivateKeyParameters privateKey, string type, Stream output, string password)
//         {
//             byte[] salt = RandomHelper.GenerateBytes(16);
//             byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);
//
//             List<PemHeaderItem> header = new List<PemHeaderItem>
//             {
//                 new PemHeaderItem
//                 {
//                     Name = "Type",
//                     Value = type
//                 },
//                 new PemHeaderItem
//                 {
//                     Name = "Salt",
//                     Value = Hex.Encode(salt).ToUpper()
//                 },
//                 new PemHeaderItem
//                 {
//                     Name = "IV",
//                     Value = Hex.Encode(iv).ToUpper()
//                 }
//             };
//
//             byte[] data = privateKey.GetEncoded();
//             byte[] padded = Pkcs7Padding.Instance.Pad(data, AES.BLOCK_SIZE);
//             byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt, 600_000);
//             byte[] enc = AES.EncryptCBC(padded, key, iv);
//             Array.Clear(key, 0, key.Length);
//             Array.Clear(data, 0, data.Length);
//             Array.Clear(padded, 0, padded.Length);
//
//             Pem.Write("DILITHIUM ENCRYPTED PRIVATE KEY", header, enc, output);
//         }
//
//         /// <summary>
//         /// Save private key to PEM file secured with a password
//         /// </summary>
//         /// <param name="privateKey">Private key</param>
//         /// <param name="type">Parameters type</param>
//         /// <param name="filePath">File path</param>
//         /// <param name="password">Password</param>
//         public static void SavePrivateKeyToPEM(DilithiumPrivateKeyParameters privateKey, string type, string filePath, string password)
//         {
//             using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
//             {
//                 SavePrivateKeyToPEM(privateKey, type, fs, password);
//             }
//         }
//
//         #endregion
//
//         #region Helpers
//
//         private static DilithiumParameters GetParameters(string type)
//         {
//             switch (type)
//             {
//                 case DILITHIUM2:
//                     return DilithiumParameters.Dilithium2;
//                 case DILITHIUM3:
//                     return DilithiumParameters.Dilithium3;
//                 case DILITHIUM5:
//                     return DilithiumParameters.Dilithium5;
//                 default:
//                     throw new InvalidOperationException();
//             }
//         }
//
//         #endregion
//     }
// }
