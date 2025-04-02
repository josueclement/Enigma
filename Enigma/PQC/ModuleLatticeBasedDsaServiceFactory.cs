using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.PQC;

/// <summary>
/// Module-Lattice-Based digital signature algorithm (ML-DSA) service factory
/// </summary>
public class ModuleLatticeBasedDsaServiceFactory : IModuleLatticeBasedDsaServiceFactory
{
    /// <inheritdoc />
    public IModuleLatticeBasedDsaService CreateMlDsa44Service()
        => new ModuleLatticeBasedDsaService(() => MLDsaParameters.ml_dsa_44);
    
    /// <inheritdoc />
    public IModuleLatticeBasedDsaService CreateMlDsa65Service()
        => new ModuleLatticeBasedDsaService(() => MLDsaParameters.ml_dsa_65);
    
    /// <inheritdoc />
    public IModuleLatticeBasedDsaService CreateMlDsa87Service()
        => new ModuleLatticeBasedDsaService(() => MLDsaParameters.ml_dsa_87);
}