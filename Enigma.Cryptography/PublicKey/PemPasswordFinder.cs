using Org.BouncyCastle.OpenSsl;

namespace Enigma.Cryptography.PublicKey;

/// <summary>
/// PEM password finder implementation
/// </summary>
/// <param name="password">Password</param>
public class PemPasswordFinder(string password) : IPasswordFinder
{
    /// <inheritdoc />
    public char[] GetPassword() => password.ToCharArray();
}