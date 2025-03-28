﻿using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service
/// </summary>
/// <param name="cipherFactory">Cipher factory</param>
/// <param name="bufferSize">Buffer size</param>
public class StreamCipherService(Func<IStreamCipher> cipherFactory, int bufferSize = 4096) : IStreamCipherService
{
    /// <inheritdoc />
    public (int keySizeInBytes, int nonceSizeInBytes) GetKeyNonceSize()
    {
        var cipher = cipherFactory();
        var engineName = cipher.AlgorithmName.Split('/').FirstOrDefault();

        if (engineName is null)
            throw new InvalidOperationException("Algorithm name not found");

        return engineName switch
        {
            "ChaCha7539" => (32, 12),
            "ChaCha20" => (32, 8),
            "Salsa20" => (32, 8),
            _ => throw new NotImplementedException($"GetKeyNonceSize not implemented for {engineName}")
        };
    }
    
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(true, parameters);
        await ProcessStreamsAsync(input, output, cipher).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);
        await ProcessStreamsAsync(input, output, cipher).ConfigureAwait(false);
    }

    private async Task ProcessStreamsAsync(Stream input, Stream output, IStreamCipher cipher)
    {
        var buffer = new byte[bufferSize];
        var outputBuffer = new byte[bufferSize];
        int bytesRead;
    
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            cipher.ProcessBytes(buffer, 0, bytesRead, outputBuffer, 0);
            await output.WriteAsync(outputBuffer, 0, bytesRead).ConfigureAwait(false);
        }
    }
}