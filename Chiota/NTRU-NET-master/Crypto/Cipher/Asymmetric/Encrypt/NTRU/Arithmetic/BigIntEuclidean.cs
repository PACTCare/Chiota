#region Directives
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic
{
    /// <summary>
    /// Extended Euclidean Algorithm in BigIntegers
    /// </summary>
    public sealed class BigIntEuclidean
    {
        #region Public Fields
        /// <summary>
        /// Coefficient X
        /// </summary>
        public BigInteger X;
        /// <summary>
        /// Coefficient Y
        /// </summary>
        public BigInteger Y;
        /// <summary>
        /// Greatest Common Divisor
        /// </summary>
        public BigInteger GCD;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public BigIntEuclidean()
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Runs the EEA on two BigIntegers
        /// </summary>
        /// <param name="A">Quotient A</param>
        /// <param name="B">Quotient B</param>
        /// <returns>Return a BigIntEuclidean object that contains the result in the variables X, Y, and GCD</returns>
        /// 
        /// <remarks>
        /// Implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm"/>Wikipedia
        /// </remarks>
        public static BigIntEuclidean Calculate(BigInteger A, BigInteger B)
        {
            BigInteger x = BigInteger.Zero;
            BigInteger lastX = BigInteger.One;
            BigInteger y = BigInteger.One;
            BigInteger lastY = BigInteger.Zero;

            while (!B.Equals(BigInteger.Zero))
            {
                BigInteger[] quotientAndRemainder = A.DivideAndRemainder(B);
                BigInteger quotient = quotientAndRemainder[0];
                BigInteger temp = A;

                A = B;
                B = quotientAndRemainder[1];

                temp = x;
                x = lastX.Subtract(quotient.Multiply(x));
                lastX = temp;

                temp = y;
                y = lastY.Subtract(quotient.Multiply(y));
                lastY = temp;
            }

            BigIntEuclidean result = new BigIntEuclidean();
            result.X = lastX;
            result.Y = lastY;
            result.GCD = A;

            return result;
        }
        #endregion
    }
}