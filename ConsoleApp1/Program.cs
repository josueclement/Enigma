﻿using System;
using System.IO;
using System.Text;
using Enigma;
using Enigma.BlockCiphers;
using Enigma.Padding;
using Enigma.PublicKey;
using Org.BouncyCastle.Utilities.Encoders;

static class Program
{
    public static void Main(string[] args)
    {
        try
        {
            var rsa = new RsaService();
            var keyPair = rsa.GenerateKeyPair(2048);
            
            var secretData = Encoding.UTF8.GetBytes("This is the secret data");
            var encryptedData = rsa.Encrypt(secretData, keyPair.Public);
            
            using var publicKeyOutputStream = new FileStream(@"C:\Temp\public.pem", FileMode.Create, FileAccess.Write);
            rsa.SaveKey(keyPair.Public, publicKeyOutputStream);
            using var privateKeyOutputStream = new FileStream(@"C:\Temp\private.pem", FileMode.Create, FileAccess.Write);
            rsa.SavePrivateKey(keyPair.Private, privateKeyOutputStream, "test1234");
            
            using var publicKeyInputStream = new FileStream(@"C:\Temp\public.pem", FileMode.Open, FileAccess.Read);
            var publicKey = rsa.LoadKey(publicKeyInputStream);
            using var privateKeyInputStream = new FileStream(@"C:\Temp\private.pem", FileMode.Open, FileAccess.Read);
            var privateKey = rsa.LoadPrivateKey(privateKeyInputStream, "test1234");
            
            var decryptedData = rsa.Decrypt(encryptedData, privateKey);
            var decryptedMessage = Encoding.UTF8.GetString(decryptedData);
        }
        catch (Exception ex)
        {
            
        }
    }
}