using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.PQC;

/// <summary>
/// Module-Lattice-Based key-encapsulation mechanism (ML-KEM) service factory
/// </summary>
public class ModuleLatticeBasedKemServiceFactory : IModuleLatticeBasedKemServiceFactory
{
    /// <inheritdoc />
    public IModuleLatticeBasedKemService CreateKem512()
        => new ModuleLatticeBasedKemService(() => MLKemParameters.ml_kem_512);
    
    /// <inheritdoc />
    public IModuleLatticeBasedKemService CreateKem768()
        => new ModuleLatticeBasedKemService(() => MLKemParameters.ml_kem_768);
    
    /// <inheritdoc />
    public IModuleLatticeBasedKemService CreateKem1024()
        => new ModuleLatticeBasedKemService(() => MLKemParameters.ml_kem_1024);
}