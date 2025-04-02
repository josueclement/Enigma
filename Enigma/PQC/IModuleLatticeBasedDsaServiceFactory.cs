namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based digital signature algorithm (ML-DSA) service factory
/// </summary>
public interface IModuleLatticeBasedDsaServiceFactory
{
    /// <summary>
    /// Create ML-DSA 44 service
    /// </summary>
    IModuleLatticeBasedDsaService CreateDsa44Service();
    
    /// <summary>
    /// Create ML-DSA 65 service
    /// </summary>
    IModuleLatticeBasedDsaService CreateDsa65Service();
    
    /// <summary>
    /// Create ML-DSA 87 service
    /// </summary>
    IModuleLatticeBasedDsaService CreateDsa87Service();
}