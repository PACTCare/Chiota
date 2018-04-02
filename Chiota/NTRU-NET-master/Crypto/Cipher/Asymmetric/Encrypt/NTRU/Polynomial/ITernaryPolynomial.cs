namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial whose coefficients are all equal to -1, 0, or 1
    /// </summary>
    public interface ITernaryPolynomial : IPolynomial
    {
        /// <summary>
        /// Multiplies the polynomial by an <c>IntegerPolynomial</c>, taking the indices mod N
        /// </summary>
        /// 
        /// <param name="Factor">A polynomial factor</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        new IntegerPolynomial Multiply(IntegerPolynomial Factor);

        /// <summary>
        /// Get the number of ones
        /// </summary>
        /// 
        /// <returns>Ones count</returns>
        int[] GetOnes();

        /// <summary>
        /// Get the number of negative ones
        /// </summary>
        /// 
        /// <returns>negative ones count</returns>
        int[] GetNegOnes();

        /// <summary>
        /// Returns the maximum number of coefficients the polynomial can have
        /// </summary>
        /// 
        /// <returns>Coefficients size</returns>
        int Size();

        /// <summary>
        /// Clear the coefficients
        /// </summary>
        new void Clear();
    }
}