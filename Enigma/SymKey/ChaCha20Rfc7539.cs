﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.SymKey
{
    /// <summary>
    /// Encrypt/Decrypt data with ChaCha20 RFC 7539
    /// </summary>
    public static class ChaCha20Rfc7539
    {
        /// <summary>
        /// ChaCha20 RFC 7539 key size
        /// </summary>
        public const int KEY_SIZE = 32;

        /// <summary>
        /// ChaCha20 RFC 7539 nonce size
        /// </summary>
        public const int NONCE_SIZE = 12;

        /// <summary>
        /// Encrypt data with ChaCha20 RFC 7539
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Key</param>
        /// <param name="nonce">Nonce</param>
        /// <returns>Encrypted data</returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] nonce)
        {
            byte[] enc = new byte[data.Length];

            ChaCha7539Engine engine = new ChaCha7539Engine();
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), nonce, 0, nonce.Length);
            engine.Init(true, parameters);
            engine.ProcessBytes(data, 0, data.Length, enc, 0);

            return enc;
        }

        /// <summary>
        /// Encrypt data with ChaCha20 RFC 7539
        /// </summary>
        /// <param name="input">Input stream to encrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="nonce">Nonce</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static void Encrypt(Stream input, Stream output, byte[] key, byte[] nonce, Action<int>? notifyProgression = null, int bufferSize = 4096)
        {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), nonce, 0, nonce.Length);
            engine.Init(true, parameters);

            int bytesRead;
            byte[] buffer = new byte[bufferSize];
            byte[] enc = new byte[bufferSize];
            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                {
                    engine.ProcessBytes(buffer, 0, bytesRead, enc, 0);
                    output.Write(enc, 0, bytesRead);

                    notifyProgression?.Invoke(bytesRead);
                }

            } while (bytesRead == bufferSize);
        }

        /// <summary>
        /// Asynchronously encrypt data with ChaCha20 RFC 7539
        /// </summary>
        /// <param name="input">Input stream to encrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="nonce">Nonce</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce, Action<int>? notifyProgression = null, int bufferSize = 4096)
        {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), nonce, 0, nonce.Length);
            engine.Init(true, parameters);

            int bytesRead;
            byte[] buffer = new byte[bufferSize];
            byte[] enc = new byte[bufferSize];
            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
                if (bytesRead > 0)
                {
                    engine.ProcessBytes(buffer, 0, bytesRead, enc, 0);
                    await output.WriteAsync(enc, 0, bytesRead).ConfigureAwait(false);

                    notifyProgression?.Invoke(bytesRead);
                }

            } while (bytesRead == bufferSize);
        }

        /// <summary>
        /// Decrypt data with ChaCha20 RFC 7539
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <param name="key">Key</param>
        /// <param name="nonce">Nonce</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] nonce)
        {
            byte[] dec = new byte[data.Length];

            ChaCha7539Engine engine = new ChaCha7539Engine();
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), nonce, 0, nonce.Length);
            engine.Init(false, parameters);
            engine.ProcessBytes(data, 0, data.Length, dec, 0);

            return dec;
        }

        /// <summary>
        /// Decrypt data with ChaCha20 RFC 7539
        /// </summary>
        /// <param name="input">Input stream to decrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="nonce">Nonce</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static void Decrypt(Stream input, Stream output, byte[] key, byte[] nonce, Action<int>? notifyProgression = null, int bufferSize = 4096)
        {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), nonce, 0, nonce.Length);
            engine.Init(false, parameters);

            int bytesRead;
            byte[] buffer = new byte[bufferSize];
            byte[] dec = new byte[bufferSize];
            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                {
                    engine.ProcessBytes(buffer, 0, bytesRead, dec, 0);
                    output.Write(dec, 0, bytesRead);

                    notifyProgression?.Invoke(bytesRead);
                }

            } while (bytesRead == bufferSize);
        }

        /// <summary>
        /// Asynchronously decrypt data with ChaCha20 RFC 7539
        /// </summary>
        /// <param name="input">Input stream to decrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="nonce">Nonce</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static async Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce, Action<int>? notifyProgression = null, int bufferSize = 4096)
        {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), nonce, 0, nonce.Length);
            engine.Init(false, parameters);

            int bytesRead;
            byte[] buffer = new byte[bufferSize];
            byte[] dec = new byte[bufferSize];
            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
                if (bytesRead > 0)
                {
                    engine.ProcessBytes(buffer, 0, bytesRead, dec, 0);
                    await output.WriteAsync(dec, 0, bytesRead).ConfigureAwait(false);

                    notifyProgression?.Invoke(bytesRead);
                }

            } while (bytesRead == bufferSize);
        }
    }
}
