namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// Polynomial interface
    /// </summary>
    public interface IPolynomial
    {
        /// <summary>
        /// Clear the state data
        /// </summary>
        void Clear();

        /// <summary>
        /// Multiplies the polynomial by an <c>IntegerPolynomial</c>,
        /// taking the indices mod <c>N</c>.
        /// </summary>
        /// 
        /// <param name="Factor">A polynomial factor</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        IntegerPolynomial Multiply(IntegerPolynomial Factor);

        /// <summary>
        /// Multiplies the polynomial by a <c>BigIntPolynomial</c>, taking the indices mod N. Does not
        /// change this polynomial but returns the result as a new polynomial.
        /// <para>Both polynomials must have the same number of coefficients.</para>
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial to multiply by</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        BigIntPolynomial Multiply(BigIntPolynomial Factor);

        /// <summary>
        /// Multiplies the polynomial by an <c>IntegerPolynomial</c>,
        /// taking the coefficient values mod <c>modulus</c> and the indices mod <c>N</c>.
        /// </summary>
        /// 
        /// <param name="Factor">A polynomial factor</param>
        /// <param name="Modulus">The modulus to apply</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        IntegerPolynomial Multiply(IntegerPolynomial Factor, int Modulus);

        /// <summary>
        /// Returns a polynomial that is equal to this polynomial (in the sense that mult(IntegerPolynomial, int) 
        /// returns equal <c>IntegerPolynomial</c>s). The new polynomial is guaranteed to be independent of the original.
        /// </summary>
        /// 
        /// <returns>The polynomial product</returns>
        IntegerPolynomial ToIntegerPolynomial();
    }
}