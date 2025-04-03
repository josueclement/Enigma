namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based key-encapsulation mechanism (ML-KEM) service factory
/// </summary>
public interface IMLKemServiceFactory
{
    /// <summary>
    /// Create ML-KEM 512 service
    /// </summary>
    IMLKemService CreateKem512();

    /// <summary>
    /// Create ML-KEM 768 service
    /// </summary>
    IMLKemService CreateKem768();

    /// <summary>
    /// Create ML-KEM 1024 service
    /// </summary>
    IMLKemService CreateKem1024();
}