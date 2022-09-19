using System;
using System.Security.Cryptography;

namespace Enigma.KDF
{
    /// <summary>
    /// Generate pseudo-random keys based on passwords with PBKDF2
    /// </summary>
    public static class PBKDF2
    {
        /// <summary>
        /// Generate a pseudo-random key based on a password and salt
        /// </summary>
        /// <param name="nbBytes">Number of bytes to generate</param>
        /// <param name="password">Password</param>
        /// <param name="salt">Salt</param>
        /// <param name="iterations">Iterations</param>
        /// <returns>Pseudo-random key</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static byte[] GenerateKeyFromPassword(int nbBytes, string password, byte[] salt, int iterations = 10000)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (iterations < 1)
                throw new ArgumentException($"Invalid iterations {iterations}", nameof(iterations));

            using (Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                return pdb.GetBytes(nbBytes);
            }
        }
    }
}
