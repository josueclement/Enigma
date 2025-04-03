namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based digital signature algorithm (ML-DSA) service factory
/// </summary>
// ReSharper disable once InconsistentNaming
public interface IMLDsaServiceFactory
{
    /// <summary>
    /// Create ML-DSA 44 service
    /// </summary>
    IMLDsaService CreateDsa44Service();
    
    /// <summary>
    /// Create ML-DSA 65 service
    /// </summary>
    IMLDsaService CreateDsa65Service();
    
    /// <summary>
    /// Create ML-DSA 87 service
    /// </summary>
    IMLDsaService CreateDsa87Service();
}