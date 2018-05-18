#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial with BigDecimal coefficients.
    /// <para>Some methods (like <c>Add</c>) change the polynomial, others (like <c>Mult</c>) do not,
    /// but return the result as a new polynomial.</para>
    /// </summary>
    internal sealed class BigDecimalPolynomial
    {
        #region Constants
        private static readonly BigDecimal ONE_HALF = new BigDecimal("0.5");
        #endregion

        #region Fields
        /// <summary>
        /// Should be marked as internal
        /// </summary>
        public BigDecimal[] Coeffs;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a new polynomial with <c>N</c> coefficients initialized to 0
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        public BigDecimalPolynomial(int N)
        {
            Coeffs = new BigDecimal[N];

            for (int i = 0; i < N; i++)
                Coeffs[i] = BigDecimal.Zero;
        }

        /// <summary>
        /// Constructs a new polynomial with a given set of coefficients
        /// </summary>
        /// <param name="Coeffs">The coefficients</param>
        private BigDecimalPolynomial(BigDecimal[] Coeffs)
        {
            this.Coeffs = Coeffs;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear the Coefficients
        /// </summary>
        public void Clear()
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = 0;
        }

        /// <summary>
        /// Divides all coefficients by 2
        /// </summary>
        public void Halve()
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = Coeffs[i].Multiply(ONE_HALF);
        }

        /// <summary>
        /// Adds another polynomial which can have a different number of coefficients.
        /// </summary>
        /// 
        /// <param name="B">The polynomial to add</param>
        public void Add(BigDecimalPolynomial B)
        {
            if (B.Coeffs.Length > Coeffs.Length)
            {
                int N = Coeffs.Length;
                Coeffs = Coeffs.CopyOf(B.Coeffs.Length);

                for (int i = N; i < Coeffs.Length; i++)
                    Coeffs[i] = BigDecimal.Zero;
            }

            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] = Coeffs[i].Add(B.Coeffs[i]);
        }

        /// <summary>
        /// Rounds all coefficients to the nearest integer
        /// </summary>
        /// 
        /// <returns>A new polynomial with <c>BigInteger</c> coefficients</returns>
        public BigIntPolynomial Round()
        {
            int N = Coeffs.Length;
            BigIntPolynomial p = new BigIntPolynomial(N);

            for (int i = 0; i < N; i++)
                p.Coeffs[i] = Coeffs[i].SetScale(0, RoundingModes.HalfEven).ToBigInteger();

            return p;
        }

        /// <summary>
        /// Makes a copy of the polynomial that is independent of the original
        /// </summary>
        /// 
        /// <returns>Cloned copy</returns>
        public BigDecimalPolynomial Clone()
        {
            return new BigDecimalPolynomial((BigDecimal[])Coeffs.Clone());
        }

        /// <summary>
        /// Multiplies the polynomial by another, taking the indices mod N.
        /// <para>Does not change this polynomial but returns the result as a new polynomial.
        /// Both polynomials must have the same number of coefficients.
        /// This method uses the <a href="http://en.wikipedia.org/wiki/Schönhage–Strassen_algorithm"/> 
        /// Schönhage–Strassen algorithm.</para>
        /// </summary>
        /// 
        /// <param name="Factor">Multiplication factor</param>
        /// 
        /// <returns>Multiplied polynomial</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the two polynomials differ in the number of coefficients</exception>
        public BigDecimalPolynomial Multiply(BigIntPolynomial Factor)
        {
            if (Factor.Coeffs.Length != Coeffs.Length)
                throw new CryptoAsymmetricException("BigDecimalPolynomial:Multiply", "Number of coefficients must be the same!", new FormatException());

            BigIntPolynomial poly1 = new BigIntPolynomial(Coeffs.Length);

            for (int i = 0; i < Coeffs.Length; i++)
                poly1.Coeffs[i] = Coeffs[i].UnScaledValue;

            int scale = Coeffs[0].Scale;

            BigIntPolynomial cBigInt = poly1.MultBig(Factor);
            BigDecimalPolynomial c = new BigDecimalPolynomial(cBigInt.Coeffs.Length);

            for (int i = 0; i < c.Coeffs.Length; i++)
                c.Coeffs[i] = new BigDecimal(cBigInt.Coeffs[i], scale);

            return c;
        }
        #endregion
    }
}