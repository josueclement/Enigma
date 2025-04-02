namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based key-encapsulation mechanism (ML-KEM) service factory
/// </summary>
public interface IModuleLatticeBasedKemServiceFactory
{
    /// <summary>
    /// Create ML-KEM 512 service
    /// </summary>
    IModuleLatticeBasedKemService CreateKem512();

    /// <summary>
    /// Create ML-KEM 768 service
    /// </summary>
    IModuleLatticeBasedKemService CreateKem768();

    /// <summary>
    /// Create ML-KEM 1024 service
    /// </summary>
    IModuleLatticeBasedKemService CreateKem1024();
}