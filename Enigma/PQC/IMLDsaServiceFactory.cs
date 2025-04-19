namespace Enigma.PQC;

/// <summary>
/// Factory interface for creating Module-Lattice-Based Digital Signature Algorithm (ML-DSA) services.
/// ML-DSA is a post-quantum cryptographic signature scheme standardized by NIST.
/// </summary>
/// <remarks>
/// ML-DSA (previously known as CRYSTALS-Dilithium) provides digital signature functionality
/// that is designed to be secure against attacks from quantum computers.
/// Different security levels (44, 65, 87) offer varying levels of security and performance trade-offs.
/// </remarks>
// ReSharper disable once InconsistentNaming
public interface IMLDsaServiceFactory
{
    /// <summary>
    /// Creates an ML-DSA signature service with security level 44 (NIST security level 2).
    /// </summary>
    /// <returns>An implementation of <see cref="IMLDsaService"/> configured for ML-DSA-44.</returns>
    /// <remarks>
    /// ML-DSA-44 provides 128 bits of security against classical attacks and 64 bits of security 
    /// against quantum attacks. It offers a good balance of security and performance for many applications.
    /// </remarks>
    IMLDsaService CreateDsa44Service();
    
    /// <summary>
    /// Creates an ML-DSA signature service with security level 65 (NIST security level 3).
    /// </summary>
    /// <returns>An implementation of <see cref="IMLDsaService"/> configured for ML-DSA-65.</returns>
    /// <remarks>
    /// ML-DSA-65 provides 192 bits of security against classical attacks and 96 bits of security 
    /// against quantum attacks. It offers enhanced security with moderate performance impact.
    /// </remarks>
    IMLDsaService CreateDsa65Service();
    
    /// <summary>
    /// Creates an ML-DSA signature service with security level 87 (NIST security level 5).
    /// </summary>
    /// <returns>An implementation of <see cref="IMLDsaService"/> configured for ML-DSA-87.</returns>
    /// <remarks>
    /// ML-DSA-87 provides 256 bits of security against classical attacks and 128 bits of security 
    /// against quantum attacks. It offers the highest security level at the cost of increased size and 
    /// computational requirements.
    /// </remarks>
    IMLDsaService CreateDsa87Service();
}