#region Directives
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial class that combines five coefficients into one <c>long</c> value for
    /// faster multiplication by a ternary polynomial.
    /// <para>Coefficients can be between 0 and 2047 and are stored in bits 0..11, 12..23, ..., 48..59 of a <c>long</c> number.</para>
    /// </summary>
    public sealed class LongPolynomial5
    {
        #region Fields
        // groups of 5 coefficients
        private long[] _coeffs;
        private int _numCoeffs;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a <c>LongPolynomial5</c> from a <c>IntegerPolynomial</c>. The two polynomials are independent of each other.
        /// </summary>
        /// 
        /// <param name="P">The original polynomial. Coefficients must be between 0 and 2047.</param>
        public LongPolynomial5(IntegerPolynomial P)
        {
            _numCoeffs = P.Coeffs.Length;

            _coeffs = new long[(_numCoeffs + 4) / 5];
            int cIdx = 0;
            int shift = 0;

            for (int i = 0; i < _numCoeffs; i++)
            {
                _coeffs[cIdx] |= ((long)P.Coeffs[i]) << shift;
                shift += 12;

                if (shift >= 60)
                {
                    shift = 0;
                    cIdx++;
                }
            }
        }

        private LongPolynomial5(long[] coeffs, int numCoeffs)
        {
            this._coeffs = coeffs;
            this._numCoeffs = numCoeffs;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Multiplies the polynomial with a <c>TernaryPolynomial</c>, taking the indices mod N and the values mod 2048.
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial factor</param>
        /// 
        /// <returns>The multiplication product</returns>
        public LongPolynomial5 Multiply(ITernaryPolynomial Factor)
        {
            long[][] prod = ArrayUtils.CreateJagged<long[][]>(5, _coeffs.Length + (Factor.Size() + 4) / 5 - 1);
            int[] pIdx = Factor.GetOnes();

            // multiply ones
            for (int i = 0; i < pIdx.Length; i++)
            {
                int cIdx = pIdx[i] / 5;
                int m = pIdx[i] - cIdx * 5;   // m = pIdx % 5

                for (int j = 0; j < _coeffs.Length; j++)
                {
                    prod[m][cIdx] = (prod[m][cIdx] + _coeffs[j]) & 0x7FF7FF7FF7FF7FFL;
                    cIdx++;
                }
            }

            pIdx = Factor.GetNegOnes();
            // multiply negative ones
            for (int i = 0; i < pIdx.Length; i++)
            {
                int cIdx = pIdx[i] / 5;
                int m = pIdx[i] - cIdx * 5;   // m = pIdx % 5

                for (int j = 0; j < _coeffs.Length; j++)
                {
                    prod[m][cIdx] = (0x800800800800800L + prod[m][cIdx] - _coeffs[j]) & 0x7FF7FF7FF7FF7FFL;
                    cIdx++;
                }
            }

            // combine shifted coefficients (5 arrays) into a single array of length prod[*].Length+1
            long[] cCoeffs = prod[0].CopyOf(prod[0].Length + 1);

            for (int m = 1; m <= 4; m++)
            {
                int shift = m * 12;
                int shift60 = 60 - shift;
                long mask = (1L << shift60) - 1;
                int pLen = prod[m].Length;

                for (int i = 0; i < pLen; i++)
                {
                    long upper, lower;
                    upper = prod[m][i] >> shift60;
                    lower = prod[m][i] & mask;

                    cCoeffs[i] = (cCoeffs[i] + (lower << shift)) & 0x7FF7FF7FF7FF7FFL;
                    int nextIdx = i + 1;
                    cCoeffs[nextIdx] = (cCoeffs[nextIdx] + upper) & 0x7FF7FF7FF7FF7FFL;
                }
            }

            // reduce indices of cCoeffs modulo numCoeffs
            int shift2 = 12 * (_numCoeffs % 5);
            for (int cIdx = _coeffs.Length - 1; cIdx < cCoeffs.Length; cIdx++)
            {
                long iCoeff;   // coefficient to shift into the [0..numCoeffs-1] range
                int newIdx;

                if (cIdx == _coeffs.Length - 1)
                {
                    iCoeff = _numCoeffs == 5 ? 0 : cCoeffs[cIdx] >> shift2;
                    newIdx = 0;
                }
                else
                {
                    iCoeff = cCoeffs[cIdx];
                    newIdx = cIdx * 5 - _numCoeffs;
                }

                int base1 = newIdx / 5;
                int m = newIdx - base1 * 5;   // m = newIdx % 5
                long lower = iCoeff << (12 * m);
                long upper = iCoeff >> (12 * (5 - m));
                cCoeffs[base1] = (cCoeffs[base1] + lower) & 0x7FF7FF7FF7FF7FFL;

                int base2 = base1 + 1;
                if (base2 < _coeffs.Length)
                    cCoeffs[base2] = (cCoeffs[base2] + upper) & 0x7FF7FF7FF7FF7FFL;
            }

            return new LongPolynomial5(cCoeffs, _numCoeffs);
        }

        /// <summary>
        /// Returns a polynomial that is equal to this polynomial (in the sense that mult(IntegerPolynomial, int) 
        /// returns equal <c>IntegerPolynomial</c>s). The new polynomial is guaranteed to be independent of the original.
        /// </summary>
        /// 
        /// <returns>The polynomial product</returns>
        public IntegerPolynomial ToIntegerPolynomial()
        {
            int[] intCoeffs = new int[_numCoeffs];
            int cIdx = 0;
            int shift = 0;

            for (int i = 0; i < _numCoeffs; i++)
            {
                intCoeffs[i] = (int)((_coeffs[cIdx] >> shift) & 2047);
                shift += 12;
                if (shift >= 60)
                {
                    shift = 0;
                    cIdx++;
                }
            }
            return new IntegerPolynomial(intCoeffs);
        }
        #endregion
    }
}