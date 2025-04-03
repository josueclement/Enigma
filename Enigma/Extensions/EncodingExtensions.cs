using System.Text;
using Enigma.DataEncoding;

namespace Enigma.Extensions;

/// <summary>
/// Encoding extensions
/// </summary>
public static class EncodingExtensions
{
    private static readonly Base64Service Base64Service = new();
    private static readonly HexService HexService = new();
    private static readonly Encoding DefaultEncoding = Encoding.Default;
    
    /// <summary>
    /// Encode bytes to base64 string
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <returns>Base64 string</returns>
    public static string ToBase64String(this byte[] bytes)
        => Base64Service.Encode(bytes);
    
    /// <summary>
    /// Decode base64 string to bytes
    /// </summary>
    /// <param name="str">Base64 encoded string</param>
    /// <returns>Bytes</returns>
    public static byte[] FromBase64String(this string str)
        => Base64Service.Decode(str);
    
    /// <summary>
    /// Encode bytes to hex string
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <returns>Hex string</returns>
    public static string ToHexString(this byte[] bytes)
        => HexService.Encode(bytes);
    
    /// <summary>
    /// Decode hex string to bytes
    /// </summary>
    /// <param name="str">Hex encoded string</param>
    /// <returns>Bytes</returns>
    public static byte[] FromHexString(this string str)
        => HexService.Decode(str);
    
    /// <summary>
    /// Decodes all the bytes in the specified byte array into a string
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <param name="encoding">Encoding. If null, Encoding.Default will be used</param>
    /// <returns>String</returns>
    public static string GetString(this byte[] bytes, Encoding? encoding = null)
        => (encoding ?? DefaultEncoding).GetString(bytes);
    
    /// <summary>
    /// Encodes all the characters in the specified string into a sequence of bytes
    /// </summary>
    /// <param name="str">String</param>
    /// <param name="encoding">Encoding. If null, Encoding.Default will be used</param>
    /// <returns>Bytes</returns>
    public static byte[] GetBytes(this string str, Encoding? encoding = null)
        => (encoding ?? DefaultEncoding).GetBytes(str);
    
    /// <summary>
    /// Decodes all the bytes in the specified byte array into a string with UTF-8 encoding
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <returns>String</returns>
    public static string GetUtf8String(this byte[] bytes)
        => GetString(bytes, Encoding.UTF8);
    
    /// <summary>
    /// Encodes all the characters in the specified string into a sequence of bytes with UTF-8 encoding
    /// </summary>
    /// <param name="str">String</param>
    /// <returns>Bytes</returns>
    public static byte[] GetUtf8Bytes(this string str)
        => GetBytes(str, Encoding.UTF8);
    
    /// <summary>
    /// Decodes all the bytes in the specified byte array into a string with ASCII encoding
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <returns>String</returns>
    public static string GetAsciiString(this byte[] bytes)
        => GetString(bytes, Encoding.ASCII);
    
    /// <summary>
    /// Encodes all the characters in the specified string into a sequence of bytes with ASCII encoding
    /// </summary>
    /// <param name="str">String</param>
    /// <returns>Bytes</returns>
    public static byte[] GetAsciiBytes(this string str)
        => GetBytes(str, Encoding.ASCII);
}