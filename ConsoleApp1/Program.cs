using System;
using Enigma.BlockCiphers;
using Enigma.Padding;
using Org.BouncyCastle.Utilities.Encoders;

static class Program
{
    public static void Main(string[] args)
    {
        try
        {
            var padding = new Pkcs7PaddingService();
            var padded = padding.Pad([12,99,7], 16);
            var unpadded = padding.UnPad(padded, 16);
        }
        catch (Exception ex)
        {
            
        }
    }
}