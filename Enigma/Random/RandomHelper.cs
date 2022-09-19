using System;
using System.Security.Cryptography;

namespace Enigma.Random
{
    /// <summary>
    /// Random data generation helper class
    /// </summary>
    public static class RandomHelper
    {
        /// <summary>
        /// Generate a byte array filled with random bytes
        /// </summary>
        /// <param name="size">Array size</param>
        /// <exception cref="ArgumentException"></exception>
        public static byte[] GenerateBytes(int size)
        {
            if (size < 0)
                throw new ArgumentException($"Invalid size {size}", nameof(size));

#if NET6_0_OR_GREATER
            return RandomNumberGenerator.GetBytes(size);
#else
            byte[] bytes = new byte[size];
            using (RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider())
            {
                provider.GetBytes(bytes);
            }

            return bytes;
#endif
        }

        /// <summary>
        /// Generate a random 16-bits integer
        /// </summary>
        /// <param name="max">Max value</param>
        /// <param name="positiveOnly">Return positive Int16 value only</param>
        public static Int16 GenerateInt16(Int16 max = Int16.MaxValue, bool positiveOnly = true)
        {
            byte[] bytes = GenerateBytes(sizeof(Int16));

            Int16 val = BitConverter.ToInt16(bytes, 0);
            if (positiveOnly)
                val = val < 0 ? (Int16)(val * -1) : val;

            return (Int16)(val % max);
        }

        /// <summary>
        /// Generate a random 32-bits integer
        /// </summary>
        /// <param name="max">Max value</param>
        /// <param name="positiveOnly">Return positive Int32 value only</param>
        public static Int32 GenerateInt32(Int32 max = Int32.MaxValue, bool positiveOnly = true)
        {
            byte[] bytes = GenerateBytes(sizeof(Int32));

            Int32 val = BitConverter.ToInt32(bytes, 0);
            if (positiveOnly)
                val = val < 0 ? val * -1 : val;

            return val % max;
        }

        /// <summary>
        /// Generate a random 64-bits integer
        /// </summary>
        /// <param name="max">Max value</param>
        /// <param name="positiveOnly">Return positive Int64 value only</param>
        public static Int64 GenerateInt64(Int64 max = Int64.MaxValue, bool positiveOnly = true)
        {
            byte[] bytes = GenerateBytes(sizeof(Int64));

            Int64 val = BitConverter.ToInt64(bytes, 0);
            if (positiveOnly)
                val = val < 0 ? val * -1 : val;

            return val % max;
        }

        /// <summary>
        /// Generate a random double-precision floating-point number
        /// </summary>
        /// <param name="max">Max value</param>
        public static double GenerateDouble(double max = 1)
        {
            byte[] bytes = GenerateBytes(sizeof(Int32));

            int val = BitConverter.ToInt32(bytes, 0);
            return new System.Random(val).NextDouble() * max;
        }

        /// <summary>
        /// Generate a random decimal number
        /// </summary>
        /// <param name="max">Max value</param>
        public static decimal GenerateDecimal(decimal max = 1)
        {
            byte[] bytes = GenerateBytes(sizeof(Int32));

            int val = BitConverter.ToInt32(bytes, 0);
            return (decimal)new System.Random(val).NextDouble() * max;
        }

        /// <summary>
        /// Generate a random single-precision floating-point number
        /// </summary>
        /// <param name="max">Max value</param>
        public static float GenerateFloat(float max = 1)
        {
            byte[] bytes = GenerateBytes(sizeof(Int32));

            int val = BitConverter.ToInt32(bytes, 0);
            return (float)new System.Random(val).NextDouble() * max;
        }
    }
}
