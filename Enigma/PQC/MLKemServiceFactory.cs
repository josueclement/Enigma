using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.PQC;

/// <summary>
/// Module-Lattice-Based key-encapsulation mechanism (ML-KEM) service factory
/// </summary>
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