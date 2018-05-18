#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial
{
    /// <summary>
    /// A <c>TernaryPolynomial</c> with a "low" number of nonzero coefficients.
    /// <para>Coefficients are represented as two arrays, one containing the indices of one-values
    /// and the other containing indices of negative ones.</para>
    /// </summary>
    internal class SparseTernaryPolynomial : ITernaryPolynomial
    {
        #region Constants
        // Number of bits to use for each coefficient. Determines the upper bound for <c>N</c>.
        private const int BITS_PER_INDEX = 11;
        #endregion

        #region Fields
        private int m_N;
        private int[] m_ones;
        private int[] m_negOnes;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a new polynomial
        /// </summary>
        /// 
        /// <param name="N">Total number of coefficients including zeros</param>
        /// <param name="Ones">Indices of coefficients equal to 1 in ascending order</param>
        /// <param name="NegOnes">Indices of coefficients equal to -1 in ascending order</param>
        public SparseTernaryPolynomial(int N, int[] Ones, int[] NegOnes)
        {
            m_N = N;
            m_ones = Ones;
            m_negOnes = NegOnes;
        }

        /// <summary>
        /// Constructs a <c>DenseTernaryPolynomial</c> from a <c>IntegerPolynomial</c>.
        /// <para>The two polynomials are independent of each other.</para>
        /// </summary>
        /// 
        /// <param name="IntPoly">The original polynomial></param>
        public SparseTernaryPolynomial(IntegerPolynomial IntPoly) :
            this(IntPoly.Coeffs)
        {
        }

        /// <summary>
        /// Constructs a new <c>SparseTernaryPolynomial</c> with a given set of coefficients.
        /// </summary>
        /// 
        /// <param name="Coeffs">The coefficients</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Throws if the coefficients are not ternary</exception>
        public SparseTernaryPolynomial(int[] Coeffs)
        {
            m_N = Coeffs.Length;
            m_ones = new int[m_N];
            m_negOnes = new int[m_N];
            int onesIdx = 0;
            int negOnesIdx = 0;

            for (int i = 0; i < m_N; i++)
            {
                int c = Coeffs[i];
                switch (c)
                {
                    case 1:
                        m_ones[onesIdx++] = i; break;
                    case -1:
                        m_negOnes[negOnesIdx++] = i; break;
                    case 0:
                        break;
                    default:
                        throw new CryptoAsymmetricException("SparseTernaryPolynomial:CTor", string.Format("Illegal value: {0}, must be one of {-1, 0, 1}", c), new FormatException());
                }
            }

            m_ones = m_ones.CopyOf(onesIdx);
            m_negOnes = m_negOnes.CopyOf(negOnesIdx);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear the coefficients
        /// </summary>
        public void Clear()
        {
            for (int i = 0; i < m_ones.Length; i++)
                m_ones[i] = 0;
            for (int i = 0; i < m_negOnes.Length; i++)
                m_negOnes[i] = 0;
        }

        /// <summary>
        /// Decodes a polynomial encoded with ToBinary()
        /// </summary>
        /// 
        /// <param name="InputStream">An input stream containing an encoded polynomial</param>
        /// <param name="N">Number of coefficients in the polynomial</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static SparseTernaryPolynomial FromBinary(MemoryStream InputStream, int N)
        {
            BinaryReader br = new BinaryReader(InputStream);
            // number of coefficients equal to 1
            int numOnes = IntUtils.ReadShort(InputStream); 
            // number of coefficients equal to -1
            int numNegOnes = IntUtils.ReadShort(InputStream); 
            int maxIndex = 1 << BITS_PER_INDEX;
            int bitsPerIndex = 32 - IntUtils.NumberOfLeadingZeros(maxIndex - 1);

            int data1Len = (numOnes * bitsPerIndex + 7) / 8;
            byte[] data1 = ArrayEncoder.ReadFullLength(InputStream, data1Len);
            int[] ones = ArrayEncoder.DecodeModQ(data1, numOnes, maxIndex);

            int data2Len = (numNegOnes * bitsPerIndex + 7) / 8;
            byte[] data2 = ArrayEncoder.ReadFullLength(InputStream, data2Len);
            int[] negOnes = ArrayEncoder.DecodeModQ(data2, numNegOnes, maxIndex);

            return new SparseTernaryPolynomial(N, ones, negOnes);
        }

        /// <summary>
        /// Generates a blinding polynomial using an IndexGenerator
        /// </summary>
        /// 
        /// <param name="Ig">An Index Generator</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Dr">The number of ones / negative ones</param>
        /// 
        /// <returns>A blinding polynomial</returns>
        public static SparseTernaryPolynomial GenerateBlindingPoly(IndexGenerator Ig, int N, int Dr)
        {
            int[] coeffs = new int[N];   // an IntegerPolynomial-style representation of the new polynomial

            int[] ones = new int[Dr];
            int i = 0;
            while (i < Dr)
            {
                int r = Ig.NextIndex();
                if (coeffs[r] == 0)
                {
                    ones[i] = r;
                    coeffs[r] = 1;
                    i++;
                }
            }

            int[] negOnes = new int[Dr];
            i = 0;

            while (i < Dr)
            {
                int r = Ig.NextIndex();
                if (coeffs[r] == 0)
                {
                    negOnes[i] = r;
                    coeffs[r] = -1;
                    i++;
                }
            }

            return new SparseTernaryPolynomial(N, ones, negOnes);
        }

        /// <summary>
        /// Generates a random polynomial with <c>numOnes</c> coefficients equal to 1,
        /// <c>numNegOnes</c> coefficients equal to -1, and the rest equal to 0.
        /// </summary>
        /// 
        /// <param name="N">Number of coefficients</param>
        /// <param name="NumOnes">Number of 1's</param>
        /// <param name="NumNegOnes">Number of -1's</param>
        /// <param name="Rng">Random number generator</param>
        /// 
        /// <returns>The new SparseTernaryPolynomial</returns>
        public static SparseTernaryPolynomial GenerateRandom(int N, int NumOnes, int NumNegOnes, IRandom Rng)
        {
            // an IntegerPolynomial-style representation of the new polynomial
            int[] coeffs = new int[N];   
            int[] ones = new int[NumOnes];
            int i = 0;

            while (i < NumOnes)
            {
                int r = Rng.Next(N - 1);

                if (coeffs[r] == 0)
                {
                    ones[i] = r;
                    coeffs[r] = 1;
                    i++;
                }
            }

            Array.Sort(ones);
            int[] negOnes = new int[NumNegOnes];
            i = 0;

            while (i < NumNegOnes)
            {
                int r = Rng.Next(N - 1);
                if (coeffs[r] == 0)
                {
                    negOnes[i] = r;
                    coeffs[r] = -1;
                    i++;
                }
            }

            Array.Sort(negOnes);

            return new SparseTernaryPolynomial(N, ones, negOnes);
        }

        /// <summary>
        /// Get the number of negative ones
        /// </summary>
        /// 
        /// <returns>negative ones count</returns>
        public int[] GetNegOnes()
        {
            return m_negOnes;
        }

        /// <summary>
        /// Get the number of ones
        /// </summary>
        /// 
        /// <returns>Ones count</returns>
        public int[] GetOnes()
        {
            return m_ones;
        }

        /// <summary>
        /// Multiplies the polynomial by an <c>IntegerPolynomial</c>,
        /// taking the indices mod <c>N</c>.
        /// </summary>
        /// 
        /// <param name="Factor">A polynomial factor</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        public IntegerPolynomial Multiply(IntegerPolynomial Factor)
        {
            int[] b = Factor.Coeffs;
            if (b.Length != m_N)
                throw new CryptoAsymmetricException("SparseTernaryPolynomial:Multiply", "Number of coefficients must be the same!", new FormatException());

            int[] c = new int[m_N];
            for (int i = 0; i < m_ones.Length; i++)
            {
                int j = m_N - 1 - m_ones[i];
                for (int k = m_N - 1; k >= 0; k--)
                {
                    c[k] += b[j];
                    j--;
                    if (j < 0)
                        j = m_N - 1;
                }
            }

            for (int i = 0; i < m_negOnes.Length; i++)
            {
                int j = m_N - 1 - m_negOnes[i];
                for (int k = m_N - 1; k >= 0; k--)
                {
                    c[k] -= b[j];
                    j--;
                    if (j < 0)
                        j = m_N - 1;
                }
            }

            return new IntegerPolynomial(c);
        }

        /// <summary>
        /// Multiplies the polynomial by an <c>IntegerPolynomial</c>,
        /// taking the coefficient values mod <c>modulus</c> and the indices mod <c>N</c>.
        /// </summary>
        /// 
        /// <param name="Factor">A polynomial factor</param>
        /// <param name="Modulus">The modulus to apply</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        public IntegerPolynomial Multiply(IntegerPolynomial Factor, int Modulus)
        {
            IntegerPolynomial c = Multiply(Factor);
            c.Mod(Modulus);

            return c;
        }

        /// <summary>
        /// Multiplies the polynomial by a <c>BigIntPolynomial</c>, taking the indices mod N. Does not
        /// change this polynomial but returns the result as a new polynomial.
        /// <para>Both polynomials must have the same number of coefficients.</para>
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial to multiply by</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        public BigIntPolynomial Multiply(BigIntPolynomial Factor)
        {
            BigInteger[] b = Factor.Coeffs;

            if (b.Length != m_N)
                throw new CryptoAsymmetricException("SparseTernaryPolynomial:Multiply", "Number of coefficients must be the same!", new FormatException());

            BigInteger[] c = new BigInteger[m_N];
            for (int i = 0; i < m_N; i++)
                c[i] = BigInteger.Zero;

            for (int i = 0; i < m_ones.Length; i++)
            {
                int j = m_N - 1 - m_ones[i];
                for (int k = m_N - 1; k >= 0; k--)
                {
                    c[k] = c[k].Add(b[j]);
                    j--;

                    if (j < 0)
                        j = m_N - 1;
                }
            }

            for (int i = 0; i < m_negOnes.Length; i++)
            {
                int j = m_N - 1 - m_negOnes[i];
                for (int k = m_N - 1; k >= 0; k--)
                {
                    c[k] = c[k].Subtract(b[j]);
                    j--;

                    if (j < 0)
                        j = m_N - 1;
                }
            }

            return new BigIntPolynomial(c);
        }

        /// <summary>
        /// Encodes the polynomial to a byte array writing <c>BITS_PER_INDEX</c> bits for each coefficient
        /// </summary>
        /// 
        /// <returns>The encoded polynomial</returns>
        public byte[] ToBinary()
        {
            int maxIndex = 1 << BITS_PER_INDEX;
            byte[] bin1 = ArrayEncoder.EncodeModQ(m_ones, maxIndex);//13l - (9,2048)
            byte[] bin2 = ArrayEncoder.EncodeModQ(m_negOnes, maxIndex);
            byte[] bin = ArrayUtils.Concat(ArrayEncoder.ToByteArray(m_ones.Length), ArrayEncoder.ToByteArray(m_negOnes.Length), bin1, bin2);

            return bin;
        }

        /// <summary>
        /// Returns a polynomial that is equal to this polynomial (in the sense that Multiply(IntegerPolynomial, int) 
        /// returns equal <c>IntegerPolynomial</c>s). The new polynomial is guaranteed to be independent of the original.
        /// </summary>
        /// 
        /// <returns>The polynomial product</returns>
        public IntegerPolynomial ToIntegerPolynomial()
        {
            int[] coeffs = new int[m_N];

            for (int i = 0; i < m_ones.Length; i++)
                coeffs[m_ones[i]] = 1;
            for (int i = 0; i < m_negOnes.Length; i++)
                coeffs[m_negOnes[i]] = -1;

            return new IntegerPolynomial(coeffs);
        }

        /// <summary>
        /// Returns the maximum number of coefficients the polynomial can have
        /// </summary>
        /// 
        /// <returns>Coefficients size</returns>
        public int Size()
        {
            return m_N;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compare this polynomial to another for equality
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

            SparseTernaryPolynomial other = (SparseTernaryPolynomial)Obj;
            if (m_N != other.m_N)
                return false;
            if (!Compare.IsEqual(m_negOnes, other.m_negOnes))
                return false;
            if (!Compare.IsEqual(m_ones, other.m_ones))
                return false;

            return true;
        }

        /// <summary>
        /// Get the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * m_N;
            hash += ArrayUtils.GetHashCode(m_negOnes);
            hash += ArrayUtils.GetHashCode(m_ones);

            return hash;
        }
        #endregion
    }
}