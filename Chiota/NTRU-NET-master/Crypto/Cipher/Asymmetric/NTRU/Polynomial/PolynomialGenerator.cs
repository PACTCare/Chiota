#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// Generates a sparse or dense mode polynomial
    /// </summary>
    public sealed class PolynomialGenerator
    {
        #region Constructor
        private PolynomialGenerator() { }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
        /// numNegOnes int equal to -1, and the rest equal to 0.
        /// </summary>
        /// 
        /// <param name="N">Number of coeffeients</param>
        /// <param name="NumOnes">Number of ones</param>
        /// <param name="NumNegOnes">Number of negative ones</param>
        /// <param name="Sparse">Create a SparseTernaryPolynomial or DenseTernaryPolynomial</param>
        /// <param name="Rng">Random number generator</param>
        /// 
        /// <returns>A ternary polynomial</returns>
        public static ITernaryPolynomial GenerateRandomTernary(int N, int NumOnes, int NumNegOnes, bool Sparse, IRandom Rng)
        {
            if (Sparse)
                return SparseTernaryPolynomial.GenerateRandom(N, NumOnes, NumNegOnes, Rng);
            else
                return DenseTernaryPolynomial.GenerateRandom(N, NumOnes, NumNegOnes, Rng);
        }
        #endregion
    }
}