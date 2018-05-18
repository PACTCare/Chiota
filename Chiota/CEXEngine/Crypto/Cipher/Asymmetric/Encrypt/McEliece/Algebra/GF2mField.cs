#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class describes operations with elements from the finite field F = GF(2^m).
    /// <para>GF(2^m)= GF(2)[A] where A is a root of irreducible polynomial with degree m,
    /// each field element B has a polynomial basis representation,
    /// is represented by a different binary polynomial of degree less than m, B = poly(A)</para>
    /// </summary>
    /// 
    /// <remarks>
    /// All operations are defined only for field with 1&lt; m &lt;32.
    /// <para>For the representation of field elements the map f: F-&gt;Z, poly(A)-&gt;poly(2) is used,
    /// where integers have the binary representation. For example: A^7+A^3+A+1 -&gt;
    /// (00...0010001011)=139 Also for elements type Integer is used.</para>
    /// </remarks>
    internal sealed class GF2mField
    {
        #region Fields
        private int m_degree = 0;
        private int m_polynomial;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The degree of the field polynomial ring over the finite field GF(2)
        /// </summary>
        public int Degree
        {
            get { return m_degree; }
        }

        /// <summary>
        /// Get: Returns the polynomial field
        /// </summary>
        public int Polynomial
        {
            get { return m_polynomial; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Create a finite field GF(2^m)
        /// </summary>
        /// 
        /// <param name="Degree">The degree of the field</param>
        public GF2mField(int Degree)
        {
            if (Degree >= 32)
                throw new ArgumentException("Error: the degree of field is too large!");
            if (Degree < 1)
                throw new ArgumentException("Error: the degree of field is non-positive!");
            
            this.m_degree = Degree;
            m_polynomial = PolynomialRingGF2.GetIrreduciblePolynomial(Degree);
        }

        /// <summary>
        /// Create a finite field GF(2^m) with the fixed field polynomial
        /// </summary>
        /// 
        /// <param name="Degree">The degree of the field</param>
        /// <param name="Polynomial">The field polynomial</param>
        public GF2mField(int Degree, int Polynomial)
        {
            if (Degree != PolynomialRingGF2.Degree(Polynomial))
                throw new ArgumentException(" Error: the degree is not correct!");
            if (!PolynomialRingGF2.IsIrreducible(Polynomial))
                throw new ArgumentException(" Error: given polynomial is reducible!");
            
            m_degree = Degree;
            m_polynomial = Polynomial;
        }

        /// <summary>
        /// Create a finite field GF(2^m) using an encoded array
        /// </summary>
        /// 
        /// <param name="Encoded">The polynomial and degree encoded as a byte array</param>
        public GF2mField(byte[] Encoded)
        {
            if (Encoded.Length != 4)
                throw new ArgumentException("byte array is not an encoded finite field");

            m_polynomial = LittleEndian.OctetsToInt(Encoded);

            if (!PolynomialRingGF2.IsIrreducible(m_polynomial))
                throw new ArgumentException("byte array is not an encoded finite field");

            m_degree = PolynomialRingGF2.Degree(m_polynomial);
        }

        /// <summary>
        /// Create a finite field GF(2^m) using another GF2mField class
        /// </summary>
        /// 
        /// <param name="Field">The GF2mField class to copy</param>
        public GF2mField(GF2mField Field)
        {
            m_degree = Field.m_degree;
            m_polynomial = Field.m_polynomial;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Return the Xor sum of two elements
        /// </summary>
        /// 
        /// <param name="A">Integer value A</param>
        /// <param name="B">Integer value b</param>
        /// 
        /// <returns>The sum: <c>a^b</c></returns>
        public int Add(int A, int B)
        {
            return A ^ B;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Clear()
        {
            m_degree = 0;
        }

        /// <summary>
        /// Help method for visual control
        /// </summary>
        /// <param name="A">Element value A</param>
        /// <returns>Element as a string value</returns>
        public String ElementToString(int A)
        {
            String s = "";
            for (int i = 0; i < m_degree; i++)
            {
                if (((byte)A & 0x01) == 0)
                    s = "0" + s;
                else
                    s = "1" + s;

                A = IntUtils.URShift(A, 1);
            }
            return s;
        }

        /// <summary>
        /// Compute exponentiation of a^k
        /// </summary>
        /// 
        /// <param name="A">The field element A</param>
        /// <param name="K">The K degree</param>
        /// 
        /// <returns>The sum: <c>a pow k</c></returns>
        public int Exp(int A, int K)
        {
            if (A == 0)
                return 0;
            if (A == 1)
                return 1;
            
            int result = 1;

            if (K < 0)
            {
                A = Inverse(A);
                K = -K;
            }
            while (K != 0)
            {
                if ((K & 1) == 1)
                    result = Multiply(result, A);

                A = Multiply(A, A);
                K = IntUtils.URShift(K, 1);
            }

            return result;
        }

        /// <summary>
        /// Returns the encoded form of this field
        /// </summary>
        /// 
        /// <returns>The encoded field</returns>
        public byte[] GetEncoded()
        {
            return LittleEndian.IntToOctets(m_polynomial);
        }

        /// <summary>
        /// Compute the multiplicative inverse of a
        /// </summary>
        /// 
        /// <param name="A">The field element A</param>
        /// 
        /// <returns>The inverse value A</returns>
        public int Inverse(int A)
        {
            int d = (1 << m_degree) - 2;

            return Exp(A, d);
        }

        /// <summary>
        /// Create a random field element using PRNG
        /// </summary>
        /// 
        /// <param name="SecRnd">The IRandom instance</param>
        /// 
        /// <returns>A random element</returns>
        public int GetRandomElement(IRandom SecRnd)
        {
            return RandomDegree.NextInt(SecRnd, 1 << m_degree);
        }

        /// <summary>
        /// Create a random non-zero field element
        /// </summary>
        /// 
        /// <param name="SecRnd">The IRandom instance</param>
        /// 
        /// <returns>A random non zero element</returns>
        public int GetRandomNonZeroElement(IRandom SecRnd)
        {
            int controltime = 1 << 20;
            int count = 0;
            int result = RandomDegree.NextInt(SecRnd, 1 << m_degree);

            while ((result == 0) && (count < controltime))
            {
                result = RandomDegree.NextInt(SecRnd, 1 << m_degree);
                count++;
            }

            if (count == controltime)
                result = 1;

            return result;
        }

        /// <summary>
        /// Test if E is encoded element of this field
        /// </summary>
        /// 
        /// <param name="E">Encoded element</param>
        /// 
        /// <returns>Returns true if e is encoded element of this field, otherwise false</returns>
        public bool IsElementOfThisField(int E)
        {
            // e is encoded element of this field iff 0<= e < |2^m|
            if (m_degree == 31)
                return E >= 0;
            
            return E >= 0 && E < (1 << m_degree);
        }

        /// <summary>
        /// Return the product of two elements
        /// </summary>
        /// 
        /// <param name="A">Integer value A</param>
        /// <param name="B">Integer value b</param>
        /// 
        /// <returns>The sum: <c>a*b</c></returns>
        public int Multiply(int A, int B)
        {
            return PolynomialRingGF2.ModMultiply(A, B, m_polynomial);
        }

        /// <summary>
        /// Compute the square root of an integer
        /// </summary>
        /// 
        /// <param name="A">The field element A</param>
        /// 
        /// <returns>The square root of A</returns>
        public int Sqrt(int A)
        {
            for (int i = 1; i < m_degree; i++)
                A = Multiply(A, A);
            
            return A;
        }
        #endregion

        #region Private Methods
        private static String PolyToString(int P)
        {
            String str = "";
            if (P == 0)
            {
                str = "0";
            }
            else
            {
                byte b = (byte)(P & 0x01);
                if (b == 1)
                    str = "1";

                P = IntUtils.URShift(P, 1);
                int i = 1;

                while (P != 0)
                {
                    b = (byte)(P & 0x01);
                    if (b == 1)
                        str = str + "+x^" + i;

                    P = IntUtils.URShift(P, 1);
                    i++;
                }
            }
            return str;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Checks if the given object is equal to this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns false if the object is not equal</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null)
                return false;
            if (!(Obj is GF2mField))
                return false;

            GF2mField other = (GF2mField)Obj;
            return ((m_degree == other.m_degree) && (m_polynomial == other.m_polynomial));
        }

        /// <summary>
        /// Get a unique hash code for this class instance 
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return m_polynomial * 31 + m_degree * 31;
        }

        /// <summary>
        /// Get a human readable form of this field
        /// </summary>
        /// 
        /// <returns>Degree and polynomial in readable form</returns>
        public override String ToString()
        {
            return "Finite Field GF(2^" + m_degree + ") = " + "GF(2)[X]/<" + PolyToString(m_polynomial) + "> ";
        }
        #endregion
    }
}
