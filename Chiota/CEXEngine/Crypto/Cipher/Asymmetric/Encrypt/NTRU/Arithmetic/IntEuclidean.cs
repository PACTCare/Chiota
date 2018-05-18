namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic
{
    /// <summary>
    /// Extended Euclidean Algorithm in integers
    /// </summary>
    internal sealed class IntEuclidean
    {
        #region Public Fields
        /// <summary>
        /// Coefficient X
        /// </summary>
        public int X;
        /// <summary>
        /// Coefficient Y
        /// </summary>
        public int Y;
        /// <summary>
        /// Greatest Common Divisor
        /// </summary>
        public int GCD;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public IntEuclidean()
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
        public static IntEuclidean Calculate(int A, int B)
        {
            int x = 0;
            int lastX = 1;
            int y = 1;
            int lastY = 0;

            while (B != 0)
            {
                int quotient = A / B;

                int temp = A;
                A = B;
                B = temp % B;

                temp = x;
                x = lastX - quotient * x;
                lastX = temp;

                temp = y;
                y = lastY - quotient * y;
                lastY = temp;
            }

            IntEuclidean result = new IntEuclidean();
            result.X = lastX;
            result.Y = lastY;
            result.GCD = A;

            return result;
        }
        #endregion
    }
}