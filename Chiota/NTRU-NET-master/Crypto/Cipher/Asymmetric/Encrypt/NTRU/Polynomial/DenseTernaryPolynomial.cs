#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial
{
    /// <summary>
    /// A <c>TernaryPolynomial</c> with a "high" number of nonzero coefficients.
    /// <para>Coefficients are represented as an array of length <c>N</c> containing ones, negative ones, and zeros.</para>
    /// </summary>
    public class DenseTernaryPolynomial : IntegerPolynomial, ITernaryPolynomial
    {
        #region Constructor
        /// <summary>
        /// Constructs a <c>DenseTernaryPolynomial</c> from a <c>IntegerPolynomial</c>. 
        /// <para>The two polynomials are independent of each other.</para>
        /// </summary>
        /// 
        /// <param name="IntPoly">The original polynomial</param>
        public DenseTernaryPolynomial(IntegerPolynomial IntPoly) :
            this(IntPoly.Coeffs)
        {
        }

        /// <summary>
        /// Constructs a new <c>DenseTernaryPolynomial</c> with a given set of coefficients.
        /// </summary>
        /// 
        /// <param name="Coeffs">The coefficients</param>
        public DenseTernaryPolynomial(int[] Coeffs) :
            base(Coeffs)
        {
        }
        #endregion
        
        #region Public Methods
        /// <summary>
        /// Generates a blinding polynomial using an IndexGenerator
        /// </summary>
        /// 
        /// <param name="Ig">An Index Generator</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Dr">The number of ones / negative ones</param>
        /// 
        /// <returns>A blinding polynomial</returns>
        public static DenseTernaryPolynomial GenerateBlindingPoly(IndexGenerator Ig, int N, int Dr)
        {
            return new DenseTernaryPolynomial(GenerateBlindingCoeffs(Ig, N, Dr));
        }

        /// <summary>
        /// Generates a random polynomial with <c>NumOnes</c> coefficients equal to 1,
        /// <c>NumNegOnes</c> coefficients equal to -1, and the rest equal to 0.
        /// </summary>
        /// 
        /// <param name="N">Number of coefficients</param>
        /// <param name="NumOnes">Number of 1's</param>
        /// <param name="NumNegOnes">Number of -1's</param>
        /// <param name="Rng">Random number generator</param>
        /// 
        /// <returns>The generated polynomial</returns>
        public static DenseTernaryPolynomial GenerateRandom(int N, int NumOnes, int NumNegOnes, IRandom Rng)
        {
            int[] arr = new int[N];
            int ct = 0;

            for (; ct < NumOnes; ct++)
                arr[ct] = 1;
            for (; ct < NumOnes + NumNegOnes; ct++)
                arr[ct] = -1;
            for (; ct < N; ct++)
                arr[ct] = 0;

            arr.Shuffle(Rng);

            return new DenseTernaryPolynomial(arr);
        }

        /// <summary>
        /// Get the number of negative ones
        /// </summary>
        /// 
        /// <returns>negative ones count</returns>
        public int[] GetNegOnes()
        {
            int N = Coeffs.Length;
            int[] negOnes = new int[N];
            int negOnesIdx = 0;

            for (int i = 0; i < N; i++)
            {
                int c = Coeffs[i];
                if (c == -1)
                    negOnes[negOnesIdx++] = i;
            }

            return negOnes.CopyOf(negOnesIdx);
        }

        /// <summary>
        /// Get the number of ones
        /// </summary>
        /// 
        /// <returns>Ones count</returns>
        public int[] GetOnes()
        {
            int N = Coeffs.Length;
            int[] ones = new int[N];
            int onesIdx = 0;

            for (int i = 0; i < N; i++)
            {
                int c = Coeffs[i];
                if (c == 1)
                    ones[onesIdx++] = i;
            }

            return ones.CopyOf(onesIdx);
        }

        /// <summary>
        /// Multiplies the polynomial with another, taking the values mod modulus and the indices mod N
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial factor</param>
        /// <param name="Modulus">The Modulus</param>
        /// 
        /// <returns>Multiplied polynomial</returns>
        public new IntegerPolynomial Multiply(IntegerPolynomial Factor, int Modulus)
        {
            // even on 32-bit systems, LongPolynomial5 multiplies faster than IntegerPolynomial
            if (Modulus == 2048)
            {
                IntegerPolynomial poly2Pos = Factor.Clone();
                poly2Pos.ModPositive(2048);
                LongPolynomial5 poly5 = new LongPolynomial5(poly2Pos);

                return poly5.Multiply(this).ToIntegerPolynomial();
            }
            else
            {
                return base.Multiply(Factor, Modulus);
            }
        }

        /// <summary>
        /// Returns the maximum number of coefficients the polynomial can have
        /// </summary>
        /// 
        /// <returns>Coefficients size</returns>
        public int Size()
        {
            return Coeffs.Length;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Generates an <c>int</c> array containing <c>dr</c> elements equal to <c>1</c>
        /// and <c>dr</c> elements equal to <c>-1</c> using an index generator.
        /// </summary>
        /// 
        /// <param name="Ig">An Index Generator</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Dr">The number of ones / negative ones</param>
        /// 
        /// <returns>An array containing numbers between <c>-1</c> and <c>1</c></returns>
        private static int[] GenerateBlindingCoeffs(IndexGenerator Ig, int N, int Dr)
        {
            int[] r = new int[N];
            for (int coeff = -1; coeff <= 1; coeff += 2)
            {
                int t = 0;
                while (t < Dr)
                {
                    int i = Ig.NextIndex();
                    if (r[i] == 0)
                    {
                        r[i] = coeff;
                        t++;
                    }
                }
            }

            return r;
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
            if (Obj.GetType().IsAssignableFrom(typeof(DenseTernaryPolynomial)))
                return Compare.AreEqual(Coeffs, ((DenseTernaryPolynomial)Obj).Coeffs);
            else
                return false;
        }

        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return this.GetHashCode();
        }

        #endregion
    }
}