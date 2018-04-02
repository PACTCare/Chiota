#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Utility;
using System.Threading.Tasks;
using System.Collections.Generic;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial of the form <c>f1*f2+f3</c>, where 
    /// <c>f1,f2,f3</c> are very sparsely populated ternary polynomials.
    /// </summary>
    public sealed class ProductFormPolynomial : IPolynomial
    {
        #region Fields
        private SparseTernaryPolynomial _f1, _f2, _f3;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a new polynomial from three sparsely populated ternary polynomials
        /// </summary>
        /// 
        /// <param name="F1">F1 polynomial</param>
        /// <param name="F2">F2 polynomial</param>
        /// <param name="F3">F3 polynomial</param>
        public ProductFormPolynomial(SparseTernaryPolynomial F1, SparseTernaryPolynomial F2, SparseTernaryPolynomial F3)
        {
            this._f1 = F1;
            this._f2 = F2;
            this._f3 = F3;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear the state data
        /// </summary>
        public void Clear()
        {
            if (_f1 != null)
                _f1.Clear();
            if (_f2 != null)
                _f2.Clear();
            if (_f3 != null)
                _f3.Clear();
        }

       /// <summary>
       /// Generates a <c>ProductFormPolynomial</c> from three random ternary polynomials.
       /// </summary>
       /// 
       /// <param name="N">Number of coefficients</param>
       /// <param name="Df1">Number of ones in the first polynomial; also the number of negative ones</param>
       /// <param name="Df2">Number of ones in the second polynomial; also the number of negative ones</param>
       /// <param name="Df3Ones">Number of ones in the third polynomial</param>
       /// <param name="Df3NegOnes">Number of negative ones in the third polynomial</param>
       /// <param name="Rng">Random number generator</param>
       /// 
       /// <returns>A random <c>ProductFormPolynomial</c></returns>
        public static ProductFormPolynomial GenerateRandom(int N, int Df1, int Df2, int Df3Ones, int Df3NegOnes, IRandom Rng)
        {
            SparseTernaryPolynomial f1 = null;
            SparseTernaryPolynomial f2 = null;
            SparseTernaryPolynomial f3 = null;

            f1 = SparseTernaryPolynomial.GenerateRandom(N, Df1, Df1, Rng);
            f2 = SparseTernaryPolynomial.GenerateRandom(N, Df2, Df2, Rng);
            f3 = SparseTernaryPolynomial.GenerateRandom(N, Df3Ones, Df3NegOnes, Rng);

            return new ProductFormPolynomial(f1, f2, f3);
        }

        /// <summary>
        /// Decodes a byte array encoded with ToBinary() to a polynomial.
        /// </summary>
        /// 
        /// <param name="Data">An encoded <c>ProductFormPolynomial</c></param>
        /// <param name="N">Number of coefficients in the polynomial</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static ProductFormPolynomial FromBinary(byte[] Data, int N)
        {
            return FromBinary(new MemoryStream(Data), N);
        }

        /// <summary>
        /// Decodes a polynomial encoded with ToBinary()
        /// </summary>
        /// 
        /// <param name="InputStrem">An input stream containing an encoded polynomial</param>
        /// <param name="N">Number of coefficients in the polynomial</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static ProductFormPolynomial FromBinary(MemoryStream InputStrem, int N)
        {
            SparseTernaryPolynomial f1;

            try
            {
                f1 = SparseTernaryPolynomial.FromBinary(InputStrem, N);
                SparseTernaryPolynomial f2 = SparseTernaryPolynomial.FromBinary(InputStrem, N);
                SparseTernaryPolynomial f3 = SparseTernaryPolynomial.FromBinary(InputStrem, N);

                return new ProductFormPolynomial(f1, f2, f3);
            }
            catch (IOException ex)
            {
                throw new NTRUException("ProductFormPolynomial:FromBinary", ex.Message, ex);
            }
        }

        /// <summary>
        /// Encodes the polynomial to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded polynomial</returns>
        public byte[] ToBinary()
        {
            byte[] f1Bin = _f1.ToBinary();
            byte[] f2Bin = _f2.ToBinary();
            byte[] f3Bin = _f3.ToBinary();

            byte[] all = f1Bin.CopyOf(f1Bin.Length + f2Bin.Length + f3Bin.Length);
            Array.Copy(f2Bin, 0, all, f1Bin.Length, f2Bin.Length);
            Array.Copy(f3Bin, 0, all, f1Bin.Length + f2Bin.Length, f3Bin.Length);

            return all;
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
            IntegerPolynomial c = _f1.Multiply(Factor);
            c = _f2.Multiply(c);
            c.Add(_f3.Multiply(Factor));

            return c;
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
        /// Multiplies the polynomial by an <c>IntegerPolynomial</c>,
        /// taking the indices mod <c>N</c>.
        /// </summary>
        /// 
        /// <param name="Factor">A polynomial factor</param>
        /// 
        /// <returns>The product of the two polynomials</returns>
        public BigIntPolynomial Multiply(BigIntPolynomial Factor)
        {
            BigIntPolynomial c = _f1.Multiply(Factor);
            c = _f2.Multiply(c);
            c.Add(_f3.Multiply(Factor));

            return c;
        }

        /// <summary>
        /// Returns a polynomial that is equal to this polynomial (in the sense that mult(IntegerPolynomial, int) 
        /// returns equal <c>IntegerPolynomial</c>s). The new polynomial is guaranteed to be independent of the original.
        /// </summary>
        /// 
        /// <returns>The polynomial product</returns>
        public IntegerPolynomial ToIntegerPolynomial()
        {
            IntegerPolynomial i = _f1.Multiply(_f2.ToIntegerPolynomial());
            i.Add(_f3);

            return i;
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
            result = prime * result + ((_f1 == null) ? 0 : _f1.GetHashCode());
            result = prime * result + ((_f2 == null) ? 0 : _f2.GetHashCode());
            result = prime * result + ((_f3 == null) ? 0 : _f3.GetHashCode());

            return result;
        }

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

            ProductFormPolynomial other = (ProductFormPolynomial)Obj;
            if (_f1 == null)
            {
                if (other._f1 != null)
                    return false;
            }
            else if (!_f1.Equals(other._f1))
            {
                return false;
            }
            if (_f2 == null)
            {
                if (other._f2 != null)
                    return false;
            }
            else if (!_f2.Equals(other._f2))
            {
                return false;
            }
            if (_f3 == null)
            {
                if (other._f3 != null)
                    return false;
            }
            else if (!_f3.Equals(other._f3))
            {
                return false;
            }

            return true;
        }
        #endregion
    }
}