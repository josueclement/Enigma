using Enigma.DataEncoding;

namespace Enigma.Extensions;

/// <summary>
/// Encoding extensions
/// </summary>
public static class EncodingExtensions
{
    private static readonly Base64Service Base64Service = new();
    private static readonly HexService HexService = new();
    
    /// <summary>
    /// Encode bytes to base64 string
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <returns>Base64 string</returns>
    public static string EncodeBase64(this byte[] bytes)
        => Base64Service.Encode(bytes);
    
    /// <summary>
    /// Decode base64 string to bytes
    /// </summary>
    /// <param name="encoded">Base64 encoded string</param>
    /// <returns>Bytes</returns>
    public static byte[] DecodeBase64(this string encoded)
        => Base64Service.Decode(encoded);
    
    /// <summary>
    /// Encode bytes to hex string
    /// </summary>
    /// <param name="bytes">Bytes</param>
    /// <returns>Hex string</returns>
    public static string EncodeHex(this byte[] bytes)
        => HexService.Encode(bytes);
    
    /// <summary>
    /// Decode hex string to bytes
    /// </summary>
    /// <param name="encoded">Hex encoded string</param>
    /// <returns>Bytes</returns>
    public static byte[] DecodeHex(this string encoded)
        => HexService.Decode(encoded);
}