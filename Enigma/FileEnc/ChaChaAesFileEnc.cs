using Enigma.IO;
using Enigma.KDF;
using Enigma.Padding;
using Enigma.Random;
using Enigma.SymKey;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.FileEnc
{
    /// <summary>
    /// Encrypt/Decrypt files with ChaCha20Rfc7539 and AES-256 (with RSA key or password)
    /// </summary>
    public static class ChaChaAesFileEnc
    {
        private const byte VERSION = 0x05;
        private const int BUFFER_SIZE = 4096;
        private const string RSA_HEADER = "CAENCR!";
        private const string PASS_HEADER = "CAENCP!";
        private const int SALT_SIZE = 16;

        #region Encrypt with key

        /// <summary>
        /// Encrypt with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="output">Output Stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            byte[] chachaKey = RandomHelper.GenerateBytes(ChaCha20Rfc7539.KEY_SIZE);
            byte[] chachaNonce = RandomHelper.GenerateBytes(ChaCha20Rfc7539.NONCE_SIZE);
            byte[] aesKey = RandomHelper.GenerateBytes(AES.KEY_SIZE);
            byte[] aesIv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            byte[] keysData;
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryHelper.WriteLV(ms, chachaKey);
                BinaryHelper.WriteLV(ms, chachaNonce);
                BinaryHelper.WriteLV(ms, aesKey);
                BinaryHelper.WriteLV(ms, aesIv);
                keysData = ms.ToArray();
            }

            byte[] encKeysData = PubKey.RSA.Encrypt(rsa, keysData);

            BinaryHelper.Write(output, RSA_HEADER, Encoding.ASCII);
            BinaryHelper.Write(output, VERSION);
            BinaryHelper.WriteLV(output, Encoding.ASCII.GetBytes(keyName));
            BinaryHelper.WriteLV(output, encKeysData);

            SymEncryptAndPad(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression);
        }

        /// <summary>
        /// Asynchronously encrypt with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="output">Output Stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(Stream input, Stream output, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            byte[] chachaKey = RandomHelper.GenerateBytes(ChaCha20Rfc7539.KEY_SIZE);
            byte[] chachaNonce = RandomHelper.GenerateBytes(ChaCha20Rfc7539.NONCE_SIZE);
            byte[] aesKey = RandomHelper.GenerateBytes(AES.KEY_SIZE);
            byte[] aesIv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            byte[] keysData;
            using (MemoryStream ms = new MemoryStream())
            {
                await BinaryHelper.WriteLVAsync(ms, chachaKey).ConfigureAwait(false);
                await BinaryHelper.WriteLVAsync(ms, chachaNonce).ConfigureAwait(false);
                await BinaryHelper.WriteLVAsync(ms, aesKey).ConfigureAwait(false);
                await BinaryHelper.WriteLVAsync(ms, aesIv).ConfigureAwait(false);
                keysData = ms.ToArray();
            }

            byte[] encKeysData = PubKey.RSA.Encrypt(rsa, keysData);

            await BinaryHelper.WriteAsync(output, RSA_HEADER, Encoding.ASCII).ConfigureAwait(false);
            await BinaryHelper.WriteAsync(output, VERSION).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, Encoding.ASCII.GetBytes(keyName)).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, encKeysData).ConfigureAwait(false);

            await SymEncryptAndPadAsync(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypt file with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(string inputFile, string outputFile, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Encrypt(fsIn, fsOut, rsa, keyName, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously encrypt file with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(string inputFile, string outputFile, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await EncryptAsync(fsIn, fsOut, rsa, keyName, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Encrypt with password

        /// <summary>
        /// Encrypt with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Passw0rd</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            byte[] chachaSalt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] chachaKey = PBKDF2.GenerateKeyFromPassword(ChaCha20Rfc7539.KEY_SIZE, password, chachaSalt, 60000);
            byte[] chachaNonce = RandomHelper.GenerateBytes(ChaCha20Rfc7539.NONCE_SIZE);

            byte[] aesSalt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] aesKey = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, aesSalt, 60000);
            byte[] aesIv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            BinaryHelper.Write(output, PASS_HEADER, Encoding.ASCII);
            BinaryHelper.Write(output, VERSION);
            BinaryHelper.WriteLV(output, chachaSalt);
            BinaryHelper.WriteLV(output, chachaNonce);
            BinaryHelper.WriteLV(output, aesSalt);
            BinaryHelper.WriteLV(output, aesIv);

            SymEncryptAndPad(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression);
        }

        /// <summary>
        /// Asynchronously encrypt with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Passw0rd</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            byte[] chachaSalt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] chachaKey = PBKDF2.GenerateKeyFromPassword(ChaCha20Rfc7539.KEY_SIZE, password, chachaSalt, 60000);
            byte[] chachaNonce = RandomHelper.GenerateBytes(ChaCha20Rfc7539.NONCE_SIZE);

            byte[] aesSalt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] aesKey = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, aesSalt, 60000);
            byte[] aesIv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            await BinaryHelper.WriteAsync(output, PASS_HEADER, Encoding.ASCII).ConfigureAwait(false);
            await BinaryHelper.WriteAsync(output, VERSION).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, chachaSalt).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, chachaNonce).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, aesSalt).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, aesIv).ConfigureAwait(false);

            await SymEncryptAndPadAsync(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypt file with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Encrypt(fsIn, fsOut, password, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously encrypt file with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await EncryptAsync(fsIn, fsOut, password, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Decrypt with key

        /// <summary>
        /// Decrypt with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delgate</param>
        public static void Decrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            input.Seek(RSA_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] keyNameData = BinaryHelper.ReadLV(input);
            byte[] encKeysData = BinaryHelper.ReadLV(input);

            notifyProgression?.Invoke(RSA_HEADER.Length + 1 + 2 * sizeof(int) + keyNameData.Length + encKeysData.Length);

            byte[] keysData = PubKey.RSA.Decrypt(rsa, encKeysData);

            byte[] chachaKey, chachaNonce, aesKey, aesIv;
            using (MemoryStream ms = new MemoryStream(keysData))
            {
                chachaKey = BinaryHelper.ReadLV(ms);
                chachaNonce = BinaryHelper.ReadLV(ms);
                aesKey = BinaryHelper.ReadLV(ms);
                aesIv = BinaryHelper.ReadLV(ms);
            }

            SymDecryptAndUnpad(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression);
        }

        /// <summary>
        /// Asynchronously decrypt with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delgate</param>
        public static async Task DecryptAsync(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            input.Seek(RSA_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] keyNameData = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
            byte[] encKeysData = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);

            notifyProgression?.Invoke(RSA_HEADER.Length + 1 + 2 * sizeof(int) + keyNameData.Length + encKeysData.Length);

            byte[] keysData = PubKey.RSA.Decrypt(rsa, encKeysData);

            byte[] chachaKey, chachaNonce, aesKey, aesIv;
            using (MemoryStream ms = new MemoryStream(keysData))
            {
                chachaKey = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                chachaNonce = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                aesKey = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                aesIv = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
            }

            await SymDecryptAndUnpadAsync(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt file with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Decrypt(string inputFile, string outputFile, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Decrypt(fsIn, fsOut, rsa, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously decrypt file with ChaCha20 and AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task DecryptAsync(string inputFile, string outputFile, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await DecryptAsync(fsIn, fsOut, rsa, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Decrypt with password

        /// <summary>
        /// Decrypt with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Decrypt(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            input.Seek(PASS_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] chachaSalt = BinaryHelper.ReadLV(input);
            byte[] chachaNonce = BinaryHelper.ReadLV(input);
            byte[] aesSalt = BinaryHelper.ReadLV(input);
            byte[] aesIv = BinaryHelper.ReadLV(input);

            notifyProgression?.Invoke(PASS_HEADER.Length + 1 + 4 * sizeof(int) + chachaSalt.Length + chachaNonce.Length + aesSalt.Length + aesIv.Length);

            byte[] chachaKey = PBKDF2.GenerateKeyFromPassword(ChaCha20Rfc7539.KEY_SIZE, password, chachaSalt, 60000);
            byte[] aesKey = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, aesSalt, 60000);

            SymDecryptAndUnpad(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression);
        }

        /// <summary>
        /// Asynchronously decrypt with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task DecryptAsync(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            input.Seek(PASS_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] chachaSalt = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
            byte[] chachaNonce = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
            byte[] aesSalt = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
            byte[] aesIv = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);

            notifyProgression?.Invoke(PASS_HEADER.Length + 1 + 4 * sizeof(int) + chachaSalt.Length + chachaNonce.Length + aesSalt.Length + aesIv.Length);

            byte[] chachaKey = PBKDF2.GenerateKeyFromPassword(ChaCha20Rfc7539.KEY_SIZE, password, chachaSalt, 60000);
            byte[] aesKey = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, aesSalt, 60000);

            await SymDecryptAndUnpadAsync(input, output, chachaKey, chachaNonce, aesKey, aesIv, notifyProgression).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt file with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Decrypt(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Decrypt(fsIn, fsOut, password, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously decrypt file with ChaCha20 and AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task DecryptAsync(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await DecryptAsync(fsIn, fsOut, password, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Encrypt/Decrypt and Pad/Unpad

        /// <summary>
        /// Encrypt with ChaCha20 and AES and pad data with Pkcs7
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="chachaKey">ChaCha20 key</param>
        /// <param name="chachaNonce">ChaCha20 nonce</param>
        /// <param name="aesKey">AES key</param>
        /// <param name="aesIv">AES Iv</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        private static void SymEncryptAndPad(Stream input, Stream output, byte[] chachaKey, byte[] chachaNonce, byte[] aesKey, byte[] aesIv, Action<int>? notifyProgression = null)
        {
            IDataPadding padding = Pkcs7Padding.Instance;

            bool padDone = false;
            int bytesRead;
            byte[] buffer = new byte[BUFFER_SIZE];

            do
            {
                bytesRead = input.Read(buffer, 0, BUFFER_SIZE);

                if (bytesRead == BUFFER_SIZE)
                {
                    GenPadXorEncryptAndWrite(output, bytesRead, buffer, chachaKey, chachaNonce, aesKey, aesIv);
                }
                else if (bytesRead > 0)
                {
                    byte[] smallBuffer = new byte[bytesRead];
                    Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                    byte[] padData = padding.Pad(smallBuffer, AES.BLOCK_SIZE);
                    padDone = true;

                    GenPadXorEncryptAndWrite(output, padData.Length, padData, chachaKey, chachaNonce, aesKey, aesIv);
                }

                notifyProgression?.Invoke(bytesRead);
            } while (bytesRead == BUFFER_SIZE);

            if (!padDone)
            {
                buffer = new byte[0];
                byte[] padData = padding.Pad(buffer, AES.BLOCK_SIZE);

                GenPadXorEncryptAndWrite(output, padData.Length, padData, chachaKey, chachaNonce, aesKey, aesIv);
            }

            BinaryHelper.WriteLV(output, new byte[0]);
        }

        /// <summary>
        /// Asynchronously encrypt with ChaCha20 and AES and pad data with Pkcs7
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="chachaKey">ChaCha20 key</param>
        /// <param name="chachaNonce">ChaCha20 nonce</param>
        /// <param name="aesKey">AES key</param>
        /// <param name="aesIv">AES Iv</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        private static async Task SymEncryptAndPadAsync(Stream input, Stream output, byte[] chachaKey, byte[] chachaNonce, byte[] aesKey, byte[] aesIv, Action<int>? notifyProgression = null)
        {
            IDataPadding padding = Pkcs7Padding.Instance;

            bool padDone = false;
            int bytesRead;
            byte[] buffer = new byte[BUFFER_SIZE];

            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);

                if (bytesRead == BUFFER_SIZE)
                {
                    await GenPadXorEncryptAndWriteAsync(output, bytesRead, buffer, chachaKey, chachaNonce, aesKey, aesIv).ConfigureAwait(false);
                }
                else if (bytesRead > 0)
                {
                    byte[] smallBuffer = new byte[bytesRead];
                    Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                    byte[] padData = padding.Pad(smallBuffer, AES.BLOCK_SIZE);
                    padDone = true;

                    await GenPadXorEncryptAndWriteAsync(output, padData.Length, padData, chachaKey, chachaNonce, aesKey, aesIv).ConfigureAwait(false);
                }

                notifyProgression?.Invoke(bytesRead);
            } while (bytesRead == BUFFER_SIZE);

            if (!padDone)
            {
                buffer = new byte[0];
                byte[] padData = padding.Pad(buffer, AES.BLOCK_SIZE);

                await GenPadXorEncryptAndWriteAsync(output, padData.Length, padData, chachaKey, chachaNonce, aesKey, aesIv).ConfigureAwait(false);
            }

            await BinaryHelper.WriteLVAsync(output, new byte[0]).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt with ChaCha20 and AES and unpad data with Pkcs7
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="chachaKey">ChaCha20 key</param>
        /// <param name="chachaNonce">ChaCha20 nonce</param>
        /// <param name="aesKey">AES key</param>
        /// <param name="aesIv">AES Iv</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        private static void SymDecryptAndUnpad(Stream input, Stream output, byte[] chachaKey, byte[] chachaNonce, byte[] aesKey, byte[] aesIv, Action<int>? notifyProgression = null)
        {
            IDataPadding padding = Pkcs7Padding.Instance;

            byte[] d1, d2;
            byte[] backup = new byte[] { };

            do
            {
                d1 = BinaryHelper.ReadLV(input);
                if (d1.Length > 0)
                {
                    output.Write(backup, 0, backup.Length);

                    byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                    d2 = BinaryHelper.ReadLV(input);
                    byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                    notifyProgression?.Invoke(2 * sizeof(int) + d1.Length + d2.Length);

                    byte[] data = new byte[rpad.Length];
                    for (int i = 0; i < rpad.Length; i++)
                        data[i] = (byte)(rpad[i] ^ xor[i]);

                    backup = new byte[data.Length];
                    Array.Copy(data, 0, backup, 0, data.Length);
                }
                else
                {
                    byte[] unpadData = padding.Unpad(backup, AES.BLOCK_SIZE);
                    output.Write(unpadData, 0, unpadData.Length);
                }

            } while (d1.Length > 0);
        }

        /// <summary>
        /// Asynchronously decrypt with ChaCha20 and AES and unpad data with Pkcs7
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="chachaKey">ChaCha20 key</param>
        /// <param name="chachaNonce">ChaCha20 nonce</param>
        /// <param name="aesKey">AES key</param>
        /// <param name="aesIv">AES Iv</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        private static async Task SymDecryptAndUnpadAsync(Stream input, Stream output, byte[] chachaKey, byte[] chachaNonce, byte[] aesKey, byte[] aesIv, Action<int>? notifyProgression = null)
        {
            IDataPadding padding = Pkcs7Padding.Instance;

            byte[] d1, d2;
            byte[] backup = new byte[] { };

            do
            {
                d1 = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
                if (d1.Length > 0)
                {
                    await output.WriteAsync(backup, 0, backup.Length).ConfigureAwait(false);

                    byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                    d2 = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
                    byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                    notifyProgression?.Invoke(2 * sizeof(int) + d1.Length + d2.Length);

                    byte[] data = new byte[rpad.Length];
                    for (int i = 0; i < rpad.Length; i++)
                        data[i] = (byte)(rpad[i] ^ xor[i]);

                    backup = new byte[data.Length];
                    Array.Copy(data, 0, backup, 0, data.Length);
                }
                else
                {
                    byte[] unpadData = padding.Unpad(backup, AES.BLOCK_SIZE);
                    await output.WriteAsync(unpadData, 0, unpadData.Length).ConfigureAwait(false);
                }

            } while (d1.Length > 0);
        }

        #endregion

        #region Double encryption pad XOR

        /// <summary>
        /// Generate a random pad, XOR data with pad, encrypt pad with ChaCha20 and encrypt XOR result with AES-256
        /// </summary>
        /// <param name="output">Output stream</param>
        /// <param name="padSize">Pad size</param>
        /// <param name="data">Data to XOR with pad</param>
        /// <param name="chachaKey">ChaCha20 key</param>
        /// <param name="chachaNonce">ChaCha20 nonce</param>
        /// <param name="aesKey">AES key</param>
        /// <param name="aesIv">AES Iv</param>
        private static void GenPadXorEncryptAndWrite(Stream output, int padSize, byte[] data, byte[] chachaKey, byte[] chachaNonce, byte[] aesKey, byte[] aesIv)
        {
            byte[] rpad = RandomHelper.GenerateBytes(padSize);
            byte[] xor = new byte[padSize];

            for (int i = 0; i < padSize; i++)
                xor[i] = (byte)(data[i] ^ rpad[i]);

            byte[] d1 = ChaCha20Rfc7539.Encrypt(rpad, chachaKey, chachaNonce);
            byte[] d2 = AES.EncryptCBC(xor, aesKey, aesIv);

            BinaryHelper.WriteLV(output, d1);
            BinaryHelper.WriteLV(output, d2);
        }

        /// <summary>
        /// Asynchronously generate a random pad, XOR data with pad, encrypt pad with ChaCha20 and encrypt XOR result with AES-256
        /// </summary>
        /// <param name="output">Output stream</param>
        /// <param name="padSize">Pad size</param>
        /// <param name="data">Data to XOR with pad</param>
        /// <param name="chachaKey">ChaCha20 key</param>
        /// <param name="chachaNonce">ChaCha20 nonce</param>
        /// <param name="aesKey">AES key</param>
        /// <param name="aesIv">AES Iv</param>
        private static async Task GenPadXorEncryptAndWriteAsync(Stream output, int padSize, byte[] data, byte[] chachaKey, byte[] chachaNonce, byte[] aesKey, byte[] aesIv)
        {
            byte[] rpad = RandomHelper.GenerateBytes(padSize);
            byte[] xor = new byte[padSize];

            for (int i = 0; i < padSize; i++)
                xor[i] = (byte)(data[i] ^ rpad[i]);

            byte[] d1 = ChaCha20Rfc7539.Encrypt(rpad, chachaKey, chachaNonce);
            byte[] d2 = AES.EncryptCBC(xor, aesKey, aesIv);

            await BinaryHelper.WriteLVAsync(output, d1).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, d2).ConfigureAwait(false);
        }

        #endregion
    }
}