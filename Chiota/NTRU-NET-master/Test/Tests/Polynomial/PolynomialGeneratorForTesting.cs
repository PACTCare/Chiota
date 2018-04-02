#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
#endregion

namespace Test.Tests.Polynomial
{
    public class PolynomialGeneratorForTesting
    {
        #region Public Methods
        /// <summary>
        /// Creates a random polynomial with <c>N</c> coefficients
        /// such that <c>-q/2 &le; c &lt; q/2</c> for each coefficient <c>c</c>.
        /// </summary>
        /// 
        /// <param name="N">The length of the polynomial</param>
        /// <param name="q">The coefficients will all be between -q/2 and q/2</param>
        /// <returns>A random polynomial</returns>
        public static IntegerPolynomial GenerateRandom(int N, int q)
        {
            Random rng = new Random();
            int[] coeffs = new int[N];
            for (int i = 0; i < N; i++)
                coeffs[i] = rng.Next(q) - q / 2;
            return new IntegerPolynomial(coeffs);
        }

        /// <summary>
        /// Creates a random polynomial with <c>N</c> coefficients
        /// such that <c>0 &le; c &lt; q</c> for each coefficient <c>c</c>.
        /// </summary>
        /// 
        /// <param name="N">The length of the polynomial</param>
        /// <param name="q">The coefficients will all be below this number</param>
        /// 
        /// <returns>A random polynomial</returns>
        public static IntegerPolynomial generateRandomPositive(int N, int q)
        {
            Random rng = new Random();
            int[] coeffs = new int[N];
            for (int i = 0; i < N; i++)
                coeffs[i] = rng.Next(q);

            return new IntegerPolynomial(coeffs);
        }

        /// <summary>
        /// Generates a polynomial with coefficients randomly selected from <c>{-1, 0, 1}</c>.
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        /// 
        /// <returns>A random polynomial</returns>
        public static DenseTernaryPolynomial generateRandom(int N)
        {
            Random rng = new Random();
            int[] coeffs = new int[N];
            for (int i = 0; i < N; i++)
                coeffs[i] = rng.Next(3) - 1;

            return new DenseTernaryPolynomial(coeffs);
        }
        #endregion
    }
}