using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.PQC;

/// <summary>
/// Factory for creating Module-Lattice-Based digital signature algorithm (ML-DSA) services.
/// This factory provides methods for creating ML-DSA services with different security levels:
/// ML-DSA-44 (NIST security level 2), ML-DSA-65 (NIST security level 3), and ML-DSA-87 (NIST security level 5).
/// </summary>
/// <remarks>
/// ML-DSA is a post-quantum cryptographic digital signature algorithm based on module lattices.
/// The different security levels (44, 65, 87) represent different parameter sets with increasing security strength.
/// </remarks>
// ReSharper disable once InconsistentNaming
public class MLDsaServiceFactory : IMLDsaServiceFactory
{
    /// <inheritdoc />
    public IMLDsaService CreateDsa44Service()
        => new MLDsaService(() => MLDsaParameters.ml_dsa_44);
    
    /// <inheritdoc />
    public IMLDsaService CreateDsa65Service()
        => new MLDsaService(() => MLDsaParameters.ml_dsa_65);
    
    /// <inheritdoc />
    public IMLDsaService CreateDsa87Service()
        => new MLDsaService(() => MLDsaParameters.ml_dsa_87);
}