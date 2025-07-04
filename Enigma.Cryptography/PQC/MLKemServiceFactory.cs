using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Cryptography.PQC;

/// <summary>
/// Factory for creating Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM) services.
/// </summary>
/// <remarks>
/// This factory provides methods to create ML-KEM service instances with different security levels:
/// <list type="bullet">
///   <item><description>ML-KEM-512: NIST security level 1 (equivalent to AES-128)</description></item>
///   <item><description>ML-KEM-768: NIST security level 3 (equivalent to AES-192)</description></item>
///   <item><description>ML-KEM-1024: NIST security level 5 (equivalent to AES-256)</description></item>
/// </list>
/// ML-KEM is a post-quantum cryptographic algorithm standardized by NIST, designed to be secure
/// against attacks from both classical and quantum computers.
/// </remarks>
// ReSharper disable once InconsistentNaming
public class MLKemServiceFactory : IMLKemServiceFactory
{
    /// <inheritdoc />
    public IMLKemService CreateKem512()
        => new MLKemService(() => MLKemParameters.ml_kem_512);
    
    /// <inheritdoc />
    public IMLKemService CreateKem768()
        => new MLKemService(() => MLKemParameters.ml_kem_768);
    
    /// <inheritdoc />
    public IMLKemService CreateKem1024()
        => new MLKemService(() => MLKemParameters.ml_kem_1024);
}