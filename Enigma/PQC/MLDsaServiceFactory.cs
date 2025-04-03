using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.PQC;

/// <summary>
/// Module-Lattice-Based digital signature algorithm (ML-DSA) service factory
/// </summary>
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