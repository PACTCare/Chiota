#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// Extends the IRandom class
    /// </summary>
    internal sealed class RandomDegree
    {
        /// <summary>
        /// Get a random number using a degree over a polynomial field
        /// </summary>
        /// <param name="SecRnd">The IRandom instance</param>
        /// <param name="N">The polynomial degree</param>
        /// 
        /// <returns>A random number</returns>
        internal static int NextInt(IRandom SecRnd, int N)
        {
            // i.e., n is a power of 2
            if ((N & -N) == N) 
                return (int)((N * (long)(IntUtils.URShift(SecRnd.Next(), 1))) >> 31);

            int bits = 0; 
            int value = 0;

            do
            {
                bits = IntUtils.URShift(SecRnd.Next(), 1);
                value = bits % N;
            }
            while (bits - value + (N - 1) < 0);

            return value;
        }
    }
}
