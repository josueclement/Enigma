using System;
using Enigma.BlockCiphers;
using Org.BouncyCastle.Utilities.Encoders;

static class Program
{
    public static void Main(string[] args)
    {
        try
        {
            // var aes = new AesCbc();
            // // aes.GenerateKeyIv(out var key, out var iv);
            // var key = Hex.Decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
            // var iv = Hex.Decode("F58C4C04D6E5F1BA779EABFB5F7BFBD6");
            // var data = Hex.Decode("ae2d8a571e03ac9c9eb76fac45af8e51");
            // var enc = aes.Encrypt(data, key, iv);
            // var res = Hex.ToHexString(enc);
            // var enc2 = Enigma.SymKey.AES.EncryptCBC(data, key, iv);
            
            // key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
            //     iv=F58C4C04D6E5F1BA779EABFB5F7BFBD6
            // plain=ae2d8a571e03ac9c9eb76fac45af8e51
            // cipher=9cfc4e967edb808d679f777bc6702c7d
            // new Enigma.Padding.Pkcs7Padding().Pad(new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0 }, 4);
        }
        catch (Exception ex)
        {
            
        }
    }
}