#region Directives
using System;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial class that combines two coefficients into one <c>long</c> value for
    /// faster multiplication in 64 bit environments.
    /// <para>Coefficients can be between 0 and 2047 and are stored in pairs in the bits 0..10 and 24..34 of a <c>long</c> number.</para>
    /// </summary>
    public sealed class LongPolynomial2
    {
        #region Fields
        /// <summary>
        /// Each representing two coefficients in the original IntegerPolynomial
        /// </summary>
        public long[] Coeffs;
        private int _numCoeffs;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a <c>LongPolynomial2</c> from a <c>IntegerPolynomial</c>. The two polynomials are independent of each other.
        /// </summary>
        /// <param name="P">The original polynomial. Coefficients must be between 0 and 2047.</param>
        public LongPolynomial2(IntegerPolynomial P)
        {
            _numCoeffs = P.Coeffs.Length;
            Coeffs = new long[(_numCoeffs + 1) / 2];
            int idx = 0;

            for (int pIdx = 0; pIdx < _numCoeffs; )
            {
                int c0 = P.Coeffs[pIdx++];
                while (c0 < 0)
                    c0 += 2048;

                long c1 = pIdx < _numCoeffs ? P.Coeffs[pIdx++] : 0;
                while (c1 < 0)
                    c1 += 2048;

                Coeffs[idx] = c0 + (c1 << 24);
                idx++;
            }
        }

        private LongPolynomial2(long[] Coeffs)
        {
            this.Coeffs = Coeffs;
        }

        private LongPolynomial2(int N)
        {
            Coeffs = new long[N];
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
        /// Makes a copy of the polynomial that is independent of the original.
        /// </summary>
        /// <returns>The cloned polynomial</returns>
        public LongPolynomial2 Clone()
        {
            LongPolynomial2 p = new LongPolynomial2((long[])Coeffs.Clone());
            p._numCoeffs = _numCoeffs;

            return p;
        }

        /// <summary>
        /// Multiplies the polynomial with another, taking the indices mod N and the values mod 2048.
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial factor</param>
        public LongPolynomial2 Multiply(LongPolynomial2 Factor)
        {
            int N = Coeffs.Length;
            if (Factor.Coeffs.Length != N || _numCoeffs != Factor._numCoeffs)
                throw new NTRUException("LongPolynomial2:Multiply", "Number of coefficients must be the same!", new FormatException());

            LongPolynomial2 c = MultRecursive(Factor);

            if (c.Coeffs.Length > N)
            {
                if (_numCoeffs % 2 == 0)
                {
                    for (int k = N; k < c.Coeffs.Length; k++)
                        c.Coeffs[k - N] = (c.Coeffs[k - N] + c.Coeffs[k]) & 0x7FF0007FFL;

                    c.Coeffs = c.Coeffs.CopyOf(N);
                }
                else
                {
                    for (int k = N; k < c.Coeffs.Length; k++)
                    {
                        c.Coeffs[k - N] = c.Coeffs[k - N] + (c.Coeffs[k - 1] >> 24);
                        c.Coeffs[k - N] = c.Coeffs[k - N] + ((c.Coeffs[k] & 2047) << 24);
                        c.Coeffs[k - N] &= 0x7FF0007FFL;
                    }

                    c.Coeffs = c.Coeffs.CopyOf(N);
                    c.Coeffs[c.Coeffs.Length - 1] &= 2047;
                }
            }

            c = new LongPolynomial2(c.Coeffs);
            c._numCoeffs = _numCoeffs;
            return c;
        }

        /// <summary>
        /// Multiplies this polynomial by 2 and applies an AND mask to the upper and 
        /// lower halves of each coefficients.
        /// </summary>
        /// 
        /// <param name="Mask">A bit mask less than 2048 to apply to each 11-bit coefficient</param>
        public void Mult2And(int Mask)
        {
            long longMask = (((long)Mask) << 24) + Mask;

            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = (Coeffs[i] << 1) & longMask;
        }

        /// <summary>
        /// Subtracts another polynomial which must have the same number of coefficients,
        /// and applies an AND mask to the upper and lower halves of each coefficients.
        /// </summary>
        /// 
        /// <param name="B">Another polynomial</param>
        /// <param name="Mask">A bit mask less than 2048 to apply to each 11-bit coefficient</param>
        public void SubAnd(LongPolynomial2 B, int Mask)
        {
            long longMask = (((long)Mask) << 24) + Mask;

            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] = (0x0800000800000L + Coeffs[i] - B.Coeffs[i]) & longMask;
        }

        #endregion

        /// <summary>
        /// Returns a polynomial that is equal to this polynomial (in the sense that mult(IntegerPolynomial, int) 
        /// returns equal <c>IntegerPolynomial</c>s). The new polynomial is guaranteed to be independent of the original.
        /// </summary>
        /// 
        /// <returns>The polynomial product</returns>
        public IntegerPolynomial ToIntegerPolynomial()
        {
            int[] intCoeffs = new int[_numCoeffs];
            int uIdx = 0;

            for (int i = 0; i < Coeffs.Length; i++)
            {
                intCoeffs[uIdx++] = (int)(Coeffs[i] & 2047);

                if (uIdx < _numCoeffs)
                    intCoeffs[uIdx++] = (int)((Coeffs[i] >> 24) & 2047);
            }

            return new IntegerPolynomial(intCoeffs);
        }

        #region Private Methods
        private void Add(LongPolynomial2 B)
        {
            // Adds another polynomial which can have a different number of coefficients.
            if (B.Coeffs.Length > Coeffs.Length)
                Coeffs = Coeffs.CopyOf(B.Coeffs.Length);

            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] = (Coeffs[i] + B.Coeffs[i]) & 0x7FF0007FFL;
        }

        private LongPolynomial2 MultRecursive(LongPolynomial2 Poly2)
        {
            // Karatsuba multiplication
            long[] a = Coeffs;
            long[] b = Poly2.Coeffs;

            int n = Poly2.Coeffs.Length;
            if (n <= 32)
            {
                int cn = 2 * n;
                LongPolynomial2 c = new LongPolynomial2(new long[cn]);
                for (int k = 0; k < cn; k++)
                {
                    for (int i = Math.Max(0, k - n + 1); i <= Math.Min(k, n - 1); i++)
                    {
                        long c0 = a[k - i] * b[i];
                        long cu = c0 & 0x7FF000000L + (c0 & 2047);
                        long co = IntUtils.URShift(c0, 48) & 2047;

                        c.Coeffs[k] = (c.Coeffs[k] + cu) & 0x7FF0007FFL;
                        c.Coeffs[k + 1] = (c.Coeffs[k + 1] + co) & 0x7FF0007FFL;
                    }
                }
                return c;
            }
            else
            {
                int n1 = n / 2;

                LongPolynomial2 a1 = new LongPolynomial2(a.CopyOf(n1));
                LongPolynomial2 a2 = new LongPolynomial2(a.CopyOfRange(n1, n));
                LongPolynomial2 b1 = new LongPolynomial2(b.CopyOf(n1));
                LongPolynomial2 b2 = new LongPolynomial2(b.CopyOfRange(n1, n));

                LongPolynomial2 A = a1.Clone();
                A.Add(a2);
                LongPolynomial2 B = b1.Clone();
                B.Add(b2);

                LongPolynomial2 c1 = a1.MultRecursive(b1);
                LongPolynomial2 c2 = a2.MultRecursive(b2);
                LongPolynomial2 c3 = A.MultRecursive(B);
                c3.Subtract(c1);
                c3.Subtract(c2);

                LongPolynomial2 c = new LongPolynomial2(2 * n);
                for (int i = 0; i < c1.Coeffs.Length; i++)
                    c.Coeffs[i] = c1.Coeffs[i] & 0x7FF0007FFL;
                for (int i = 0; i < c3.Coeffs.Length; i++)
                    c.Coeffs[n1 + i] = (c.Coeffs[n1 + i] + c3.Coeffs[i]) & 0x7FF0007FFL;
                for (int i = 0; i < c2.Coeffs.Length; i++)
                    c.Coeffs[2 * n1 + i] = (c.Coeffs[2 * n1 + i] + c2.Coeffs[i]) & 0x7FF0007FFL;

                return c;
            }
        }

        private void Subtract(LongPolynomial2 B)
        {
            // Subtracts another polynomial which can have a different number of coefficients
            if (B.Coeffs.Length > Coeffs.Length)
                Coeffs = Coeffs.CopyOf(B.Coeffs.Length);
            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] = (0x0800000800000L + Coeffs[i] - B.Coeffs[i]) & 0x7FF0007FFL;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compare this big integer polynomial to another for equality
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj.GetType().IsAssignableFrom(typeof(LongPolynomial2)))
                return Coeffs.Equals(((LongPolynomial2)Obj).Coeffs);
            else
                return false;
        }
        #endregion
    }
}