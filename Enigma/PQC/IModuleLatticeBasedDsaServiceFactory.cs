namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based digital signature algorithm (ML-DSA) service factory
/// </summary>
public interface IModuleLatticeBasedDsaServiceFactory
{
    /// <summary>
    /// Create ML-DSA 44 service
    /// </summary>
    IModuleLatticeBasedDsaService CreateMlDsa44Service();
    
    /// <summary>
    /// Create ML-DSA 65 service
    /// </summary>
    IModuleLatticeBasedDsaService CreateMlDsa65Service();
    
    /// <summary>
    /// Create ML-DSA 87 service
    /// </summary>
    IModuleLatticeBasedDsaService CreateMlDsa87Service();
}