namespace Enigma.Cryptography.PQC;

/// <summary>
/// Factory interface for creating Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM) services.
/// </summary>
/// <remarks>
/// ML-KEM is a post-quantum cryptographic algorithm standardized by NIST that provides
/// key encapsulation functionality resistant to attacks from quantum computers.
/// This factory supports creating services with different security levels (512, 768, and 1024).
/// </remarks>
// ReSharper disable once InconsistentNaming
public interface IMLKemServiceFactory
{
    /// <summary>
    /// Creates an ML-KEM service with security level 512.
    /// </summary>
    /// <returns>An ML-KEM service configured for the 512 security level (NIST security level 1).</returns>
    /// <remarks>
    /// ML-KEM 512 offers the lowest security level in the ML-KEM family, providing
    /// approximately 128 bits of classical security and 64 bits of quantum security.
    /// It has the smallest key sizes and best performance among the ML-KEM variants.
    /// </remarks>
    IMLKemService CreateKem512();

    /// <summary>
    /// Creates an ML-KEM service with security level 768.
    /// </summary>
    /// <returns>An ML-KEM service configured for the 768 security level (NIST security level 3).</returns>
    /// <remarks>
    /// ML-KEM 768 offers a medium security level in the ML-KEM family, providing
    /// approximately 192 bits of classical security and 96 bits of quantum security.
    /// It provides a balance between security and performance.
    /// </remarks>
    IMLKemService CreateKem768();

    /// <summary>
    /// Creates an ML-KEM service with security level 1024.
    /// </summary>
    /// <returns>An ML-KEM service configured for the 1024 security level (NIST security level 5).</returns>
    /// <remarks>
    /// ML-KEM 1024 offers the highest security level in the ML-KEM family, providing
    /// approximately 256 bits of classical security and 128 bits of quantum security.
    /// It has the largest key sizes and lowest performance among the ML-KEM variants.
    /// </remarks>
    IMLKemService CreateKem1024();
}