namespace Enigma.DataEncoding;

/// <summary>
/// Defines the contract for services that handle data encoding and decoding operations.
/// Implementations of this interface can provide various encoding schemes such as Base64, 
/// Hex, or custom encoding algorithms.
/// </summary>
public interface IEncodingService
{
    /// <summary>
    /// Encodes binary data into a string representation using the implementation's encoding scheme.
    /// </summary>
    /// <param name="data">The raw binary data to be encoded. Cannot be null.</param>
    /// <returns>A string containing the encoded representation of the input data.</returns>
    string Encode(byte[] data);
    
    /// <summary>
    /// Decodes a previously encoded string back into its original binary representation.
    /// </summary>
    /// <param name="data">The encoded string to be decoded. Cannot be null or empty.</param>
    /// <returns>A byte array containing the decoded binary data.</returns>
    byte[] Decode(string data);
}