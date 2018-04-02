#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial with {@link BigInteger} coefficients.
    /// <para>Some methods (like <c>add</c>) change the polynomial, others (like <c>mult</c>) do not,
    /// but return the result as a new polynomial.</para>
    /// </summary>
    public sealed class BigIntPolynomial
    {
        #region Fields
        private static readonly double LOG_10_2 = Math.Log10(2);
        /// <summary>
        /// should be marked as internal
        /// </summary>
        public BigInteger[] Coeffs;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a new polynomial with <c>N</c> coefficients initialized to 0.
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        public BigIntPolynomial(int N)
        {
            Coeffs = new BigInteger[N];

            for (int i = 0; i < N; i++)
                Coeffs[i] = BigInteger.Zero;
        }

        /// <summary>
        /// Constructs a new polynomial with a given set of coefficients.
        /// </summary>
        /// 
        /// <param name="Coeffs">The coefficients</param>
        public BigIntPolynomial(BigInteger[] Coeffs)
        {
            this.Coeffs = Coeffs;
        }

        /// <summary>
        /// Constructs a <c>BigIntPolynomial</c> from a <c>IntegerPolynomial</c>. The two polynomials are
        /// independent of each other.
        /// </summary>
        /// 
        /// <param name="P">The original polynomial</param>
        public BigIntPolynomial(IntegerPolynomial P)
        {
            Coeffs = new BigInteger[P.Coeffs.Length];
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = BigInteger.ValueOf(P.Coeffs[i]);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds another polynomial which can have a different number of coefficients.
        /// </summary>
        /// 
        /// <param name="B">The polynomial to add</param>
        public void Add(BigIntPolynomial B)
        {
            if (B.Coeffs.Length > Coeffs.Length)
            {
                int N = Coeffs.Length;
                Coeffs = Coeffs.CopyOf(B.Coeffs.Length);

                for (int i = N; i < Coeffs.Length; i++)
                    Coeffs[i] = BigInteger.Zero;
            }

            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] = Coeffs[i].Add(B.Coeffs[i]);
        }

        /// <summary>
        /// Clear the Coefficients
        /// </summary>
        public void Clear()
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = 0;
        }

        /// <summary>
        /// Makes a copy of the polynomial that is independent of the original.
        /// </summary>
        /// <returns>The cloned polynomial</returns>
        public BigIntPolynomial Clone()
        {
            return new BigIntPolynomial((BigInteger[])Coeffs.Clone());
        }

        /// <summary>
        /// Divides each coefficient by a <c>BigInteger</c> and rounds the result to the nearest whole number.
        /// <para>Does not return a new polynomial but modifies this polynomial.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">The divisor</param>
        public void Divide(BigInteger Divisor)
        {
            BigInteger d = Divisor.Add(BigInteger.One.ShiftRight(1));   // d = ceil(divisor/2)

            for (int i = 0; i < Coeffs.Length; i++)
            {
                Coeffs[i] = Coeffs[i].Signum() > 0 ? Coeffs[i].Add(d) : Coeffs[i].Add(d.Negate());
                Coeffs[i] = Coeffs[i].Divide(Divisor);
            }
        }

        /// <summary>
        /// Divides each coefficient by a <c>BigDecimal</c> and rounds the result to <c>decimalPlaces</c> places.
        /// </summary>
        /// 
        /// <param name="Divisor">The divisor</param>
        /// <param name="DecimalPlaces">The number of fractional digits to round the result to</param>
        /// 
        /// <returns>The polynomial product</returns>
        public BigDecimalPolynomial Divide(BigDecimal Divisor, int DecimalPlaces)
        {
            BigInteger max = MaxCoeffAbs();
            int coeffLength = (int)(max.BitLength * LOG_10_2) + 1;
            // factor = 1/divisor
            BigDecimal factor = BigDecimal.One.Divide(Divisor, coeffLength + DecimalPlaces + 1, RoundingModes.HalfEven);
            // multiply each coefficient by factor
            BigDecimalPolynomial p = new BigDecimalPolynomial(Coeffs.Length);

            for (int i = 0; i < Coeffs.Length; i++)
            {
                // multiply, then truncate after decimalPlaces so subsequent operations aren't slowed down
                p.Coeffs[i] = new BigDecimal(Coeffs[i]).Multiply(factor).SetScale(DecimalPlaces, RoundingModes.HalfEven);
            }

            return p;
        }

        /// <summary>
        /// Returns the base10 length of the largest coefficient.
        /// </summary>
        /// 
        /// <returns>Length of the longest coefficient</returns>
        public int GetMaxCoeffLength()
        {
            return (int)(MaxCoeffAbs().BitLength * LOG_10_2) + 1;
        }

        /// <summary>
        /// Takes each coefficient modulo a number.
        /// </summary>
        /// 
        /// <param name="Modulus">The modulus</param>
        public void Mod(BigInteger Modulus)
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = Coeffs[i].Mod(Modulus);
        }

        /// <summary>
        /// Multiplies each coefficient by a <c>BigInteger</c>. Does not return a new polynomial but modifies this polynomial.
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial factor</param>
        public void Multiply(BigInteger Factor)
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = Coeffs[i].Multiply(Factor);
        }

        /// <summary>
        /// Multiplies the polynomial by another, taking the indices mod N.
        /// <para>Does not change this polynomial but returns the result as a new polynomial.
        /// Both polynomials must have the same number of coefficients.
        /// This method is designed for large polynomials and uses Schönhage-Strassen multiplication
        /// in combination with <a href="http://en.wikipedia.org/wiki/Kronecker_substitution">Kronecker substitution</a>.
        /// See <a href="http://math.stackexchange.com/questions/58946/karatsuba-vs-schonhage-strassen-for-multiplication-of-polynomials#58955">here</a> for details.</para>
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial to multiply by</param>
        /// 
        /// <returns>The product polynomial</returns>
        public BigIntPolynomial MultBig(BigIntPolynomial Factor)
        {
            int N = Coeffs.Length;

            // determine #bits needed per coefficient
            int logMinDigits = 32 - IntUtils.NumberOfLeadingZeros(N - 1);
            int maxLengthA = 0;

            for (int i = 0; i < Coeffs.Length; i++)
            {
                BigInteger coeff = Coeffs[i];
                maxLengthA = Math.Max(maxLengthA, coeff.BitLength);
            }

            int maxLengthB = 0;
            for (int i = 0; i < Factor.Coeffs.Length; i++)
            {
                BigInteger coeff = Factor.Coeffs[i];
                maxLengthB = Math.Max(maxLengthB, coeff.BitLength);
            }

            int k = logMinDigits + maxLengthA + maxLengthB + 1;   // in bits
            k = (k + 31) / 32;   // in ints

            // encode each polynomial into an int[]
            int aDeg = Degree();
            int bDeg = Factor.Degree();

            if (aDeg < 0 || bDeg < 0)
                return new BigIntPolynomial(N);   // return zero

            int[] aInt = ToIntArray(this, k);
            int[] bInt = ToIntArray(Factor, k);
            int[] cInt = SchonhageStrassen.Multiply(aInt, bInt);
            // decode poly coefficients from the product
            BigInteger _2k = BigInteger.One.ShiftLeft(k * 32);
            BigIntPolynomial cPoly = new BigIntPolynomial(N);

            for (int i = 0; i < 2 * N - 1; i++)
            {
                int[] coeffInt = cInt.CopyOfRange(i * k, (i + 1) * k);
                BigInteger coeff = SchonhageStrassen.ToBigInteger(coeffInt);
                if (coeffInt[k - 1] < 0)
                {   // if coeff > 2^(k-1)
                    coeff = coeff.Subtract(_2k);
                    // add 2^k to cInt which is the same as subtracting coeff
                    bool carry = false;
                    int cIdx = (i + 1) * k;

                    do
                    {
                        cInt[cIdx]++;
                        carry = cInt[cIdx] == 0;
                        cIdx++;
                    } while (carry);
                }
                cPoly.Coeffs[i % N] = cPoly.Coeffs[i % N].Add(coeff);
            }

            int aSign = Coeffs[aDeg].Signum();
            int bSign = Factor.Coeffs[bDeg].Signum();

            if (aSign * bSign < 0)
            {
                for (int i = 0; i < N; i++)
                    cPoly.Coeffs[i] = cPoly.Coeffs[i].Negate();
            }

            return cPoly;
        }

        /// <summary>
        /// Multiplies the polynomial by another, taking the indices mod N.
        /// <para>Does not change this polynomial but returns the result as a new polynomial.
        /// Both polynomials must have the same number of coefficients.
        /// This method is designed for smaller polynomials and uses 
        /// <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba multiplication</a>.</para>
        /// </summary>
        /// 
        /// <param name="Factor">he polynomial to multiply by</param>
        /// 
        /// <returns>The product polynomial</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Throws if the two polynomials have a different number of coefficients</exception>
        public BigIntPolynomial MultSmall(BigIntPolynomial Factor)
        {
            int N = Coeffs.Length;

            if (Factor.Coeffs.Length != N)
                throw new CryptoAsymmetricException("BigIntPolynomial:Multiply", "Number of coefficients must be the same!", new FormatException());

            BigIntPolynomial c = MultRecursive(Factor);

            if (c.Coeffs.Length > N)
            {
                for (int k = N; k < c.Coeffs.Length; k++)
                    c.Coeffs[k - N] = c.Coeffs[k - N].Add(c.Coeffs[k]);
                c.Coeffs = c.Coeffs.CopyOf(N);
            }

            return c;
        }

        /// <summary>
        /// Subtracts another polynomial which can have a different number of coefficients.
        /// </summary>
        /// 
        /// <param name="B">The polynomial to subtract</param>
        public void Subtract(BigIntPolynomial B)
        {
            if (B.Coeffs.Length > Coeffs.Length)
            {
                int N = Coeffs.Length;
                Coeffs = Coeffs.CopyOf(B.Coeffs.Length);

                for (int i = N; i < Coeffs.Length; i++)
                    Coeffs[i] = BigInteger.Zero;
            }

            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] = Coeffs[i].Subtract(B.Coeffs[i]);
        }
        #endregion

        #region Private Methods
        private void AddShifted(int[] A, int[] B, int NumElements)
        {
            // drops elements of b that are shifted outside the valid range
            bool carry = false;
            int i = 0;

            while (i < Math.Min(B.Length, A.Length - NumElements))
            {
                int ai = A[i + NumElements];
                int sum = ai + B[i];

                if (carry)
                    sum++;

                carry = (IntUtils.URShift(sum, 31) < IntUtils.URShift(ai, 31) + IntUtils.URShift(B[i], 31));   // carry if signBit(sum) < signBit(a)+signBit(b)
                A[i + NumElements] = sum;
                i++;
            }

            i += NumElements;
            while (carry)
            {
                A[i]++;
                carry = A[i] == 0;
                i++;
            }
        }

        private int Degree()
        {
            // Returns the degree of the polynomial or -1 if the degree is negative 
            int degree = Coeffs.Length - 1;

            while (degree >= 0 && Coeffs[degree].Equals(BigInteger.Zero))
                degree--;
            return degree;
        }

        private BigInteger MaxCoeffAbs()
        {
            BigInteger max = Coeffs[0].Abs();

            for (int i = 1; i < Coeffs.Length; i++)
            {
                BigInteger coeff = Coeffs[i].Abs();
                if (coeff.CompareTo(max) > 0)
                    max = coeff;
            }

            return max;
        }

        private BigIntPolynomial MultRecursive(BigIntPolynomial Factor)
        {
            // Karatsuba multiplication
            BigInteger[] a = Coeffs;
            BigInteger[] b = Factor.Coeffs;

            int n = Factor.Coeffs.Length;
            if (n <= 1)
            {
                BigInteger[] c = (BigInteger[])Coeffs.Clone();
                for (int i = 0; i < Coeffs.Length; i++)
                    c[i] = c[i].Multiply(Factor.Coeffs[0]);

                return new BigIntPolynomial(c);
            }
            else
            {
                int n1 = n / 2;

                BigIntPolynomial a1 = new BigIntPolynomial(a.CopyOf(n1));
                BigIntPolynomial a2 = new BigIntPolynomial(a.CopyOfRange(n1, n));
                BigIntPolynomial b1 = new BigIntPolynomial(b.CopyOf(n1));
                BigIntPolynomial b2 = new BigIntPolynomial(b.CopyOfRange(n1, n));

                BigIntPolynomial A = (BigIntPolynomial)a1.Clone();
                A.Add(a2);
                BigIntPolynomial B = (BigIntPolynomial)b1.Clone();
                B.Add(b2);

                BigIntPolynomial c1 = a1.MultRecursive(b1);
                BigIntPolynomial c2 = a2.MultRecursive(b2);
                BigIntPolynomial c3 = A.MultRecursive(B);
                c3.Subtract(c1);
                c3.Subtract(c2);
                BigIntPolynomial c = new BigIntPolynomial(2 * n - 1);

                for (int i = 0; i < c1.Coeffs.Length; i++)
                    c.Coeffs[i] = c1.Coeffs[i];
                for (int i = 0; i < c3.Coeffs.Length; i++)
                    c.Coeffs[n1 + i] = c.Coeffs[n1 + i].Add(c3.Coeffs[i]);
                for (int i = 0; i < c2.Coeffs.Length; i++)
                    c.Coeffs[2 * n1 + i] = c.Coeffs[2 * n1 + i].Add(c2.Coeffs[i]);

                return c;
            }
        }

        private void SubShifted(int[] A, int[] B, int NumElements)
        {
            bool carry = false;
            int i = 0;
            // drops elements of b that are shifted outside the valid range
            while (i < Math.Min(B.Length, A.Length - NumElements))
            {
                int ai = A[i + NumElements];
                int diff = ai - B[i];

                if (carry)
                    diff--;

                carry = (IntUtils.URShift(diff, 31) > IntUtils.URShift(A[i], 31) - IntUtils.URShift(B[i], 31));   // carry if signBit(diff) > signBit(a)-signBit(b)
                A[i + NumElements] = diff;
                i++;
            }

            i += NumElements;
            while (carry)
            {
                A[i]--;
                carry = A[i] == -1;
                i++;
            }
        }

        private int[] ToIntArray(BigIntPolynomial A, int K)
        {
            int N = A.Coeffs.Length;
            int sign = A.Coeffs[A.Degree()].Signum();
            int[] aInt = new int[N * K];

            for (int i = N - 1; i >= 0; i--)
            {
                int[] cArr = SchonhageStrassen.ToIntArray(A.Coeffs[i].Abs());

                if (A.Coeffs[i].Signum() * sign < 0)
                    SubShifted(aInt, cArr, i * K);
                else
                    AddShifted(aInt, cArr, i * K);
            }

            return aInt;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + Coeffs.GetHashCode();
            return result;
        }

        /// <summary>
        /// Compare this big integer polynomial to another for equality
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null)
                return false;

            BigIntPolynomial other = (BigIntPolynomial)Obj;
            for (int i = 0; i < Coeffs.Length; i++ )
            {
                if (!Coeffs[i].Equals(other.Coeffs[i]))
                    return false;
            }
            
            return true;
        }
        #endregion
    }
}