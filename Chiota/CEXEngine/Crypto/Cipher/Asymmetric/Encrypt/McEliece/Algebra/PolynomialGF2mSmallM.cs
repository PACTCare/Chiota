#region Directives
using System;
using System.Threading;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class describes operations with polynomials from the ring R = GF(2^m)[X], where 2 &lt;= m &lt;=31
    /// </summary>
    internal sealed class PolynomialGF2mSmallM
    {
        #region Constants
        /// <summary>
        /// Constant used for polynomial construction
        /// </summary>
        public const char RANDOM_IRREDUCIBLE_POLYNOMIAL = 'I';
        #endregion

        #region Fields
        // the finite field GF(2^m)
        private GF2mField m_field;
        // the degree of this polynomial
        private int m_degree;
        /* For the polynomial representation the map f: R->Z*, <c>poly(X) -> [coef_0, coef_1, ...]</c> is used, where
           <c>coef_i</c> is the <c>i</c>th coefficient of the polynomial represented as int (see GF2mField). 
           The polynomials are stored as int arrays. */
        private int[] m_coefficients;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the degree of this polynomial
        /// </summary>
        public int Degree
        {
            get
            {
                int d = m_coefficients.Length - 1;
                if (m_coefficients[d] == 0)
                    return -1;

                return d;
            }
        }

        /// <summary>
        /// Get: Returns the finite field GF(2^m)
        /// </summary>
        public GF2mField Field
        {
            get { return m_field; }
        }

        /// <summary>
        /// Get: Returns the head coefficient of this polynomial
        /// </summary>
        public int Head
        {
            get
            {
                if (m_degree == -1)
                    return 0;

                return m_coefficients[m_degree];
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Construct the zero polynomial over the finite field GF(2^m)
        /// </summary>
        /// 
        /// <param name="Field">The finite field GF(2^m)</param>
        public PolynomialGF2mSmallM(GF2mField Field)
        {
            m_field = Field;
            m_degree = -1;
            m_coefficients = new int[1];
        }

        /// <summary>
        /// Construct a polynomial over the finite field GF(2^m)
        /// </summary>
        /// 
        /// <param name="Field">The finite field GF(2^m)</param>
        /// <param name="Degree">The  degree of polynomial</param>
        /// <param name="PolynomialType">The  type of polynomial</param>
        /// <param name="Rand">The IRandom instance</param>
        public PolynomialGF2mSmallM(GF2mField Field, int Degree, char PolynomialType, IRandom Rand)
        {
            m_field = Field;

            switch (PolynomialType)
            {
                case PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL:
                    m_coefficients = CreateRandomIrreduciblePolynomial(Degree, Rand);
                    break;
                default:
                    throw new ArgumentException(" Error: type " + PolynomialType + " is not defined for GF2smallmPolynomial");
            }

            ComputeDegree();
        }

        /// <summary>
        /// Construct a monomial of the given degree over the finite field GF(2^m)
        /// </summary>
        /// 
        /// <param name="Field">The finite field GF(2^m)</param>
        /// <param name="Degree">The degree of the monomial</param>
        public PolynomialGF2mSmallM(GF2mField Field, int Degree)
        {
            m_field = Field;
            m_degree = Degree;
            m_coefficients = new int[Degree + 1];
            m_coefficients[Degree] = 1;
        }

        /// <summary>
        /// Construct the polynomial over the given finite field GF(2^m) from the given coefficient vector
        /// </summary>
        /// 
        /// <param name="Field">The finite field GF2m</param>
        /// <param name="Coeffs">The coefficient vector</param>
        public PolynomialGF2mSmallM(GF2mField Field, int[] Coeffs)
        {
            m_field = Field;
            m_coefficients = NormalForm(Coeffs);
            ComputeDegree();
        }

        /// <summary>
        /// Create a polynomial over the finite field GF(2^m)
        /// </summary>
        /// 
        /// <param name="Field">The finite field GF(2^m)</param>
        /// <param name="Encoded">The polynomial in byte array form</param>
        public PolynomialGF2mSmallM(GF2mField Field, byte[] Encoded)
        {
            m_field = Field;
            int d = 8;
            int count = 1;
            while (Field.Degree > d)
            {
                count++;
                d += 8;
            }

            if ((Encoded.Length % count) != 0)
                throw new ArgumentException("PolynomialGF2mSmallM: byte array is not encoded polynomial over given finite field GF2m!");

            m_coefficients = new int[Encoded.Length / count];
            count = 0;
            for (int i = 0; i < m_coefficients.Length; i++)
            {
                for (int j = 0; j < d; j += 8)
                    m_coefficients[i] ^= (Encoded[count++] & 0x000000ff) << j;

                if (!this.m_field.IsElementOfThisField(m_coefficients[i]))
                    throw new ArgumentException(" PolynomialGF2mSmallM: byte array is not encoded polynomial over given finite field GF2m!");
            }

            // if HC = 0 for non-zero polynomial, returns error
            if ((m_coefficients.Length != 1) && (m_coefficients[m_coefficients.Length - 1] == 0))
                throw new ArgumentException("PolynomialGF2mSmallM: byte array is not encoded polynomial over given finite field GF2m");

            ComputeDegree();
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// 
        /// <param name="Gf">The PolynomialGF2mSmallM to copy</param>
        public PolynomialGF2mSmallM(PolynomialGF2mSmallM Gf)
        {
            // field needs not to be cloned since it is immutable
            m_field = Gf.m_field;
            m_degree = Gf.m_degree;
            m_coefficients = IntUtils.DeepCopy(Gf.m_coefficients);
        }

        /// <summary>
        /// Create a polynomial over the finite field GF(2^m) out of the given coefficient vector
        /// <para>The finite field is also obtained from the GF2mVector</para>
        /// </summary>
        /// 
        /// <param name="Vect"></param>
        public PolynomialGF2mSmallM(GF2mVector Vect) :
            this(Vect.Field, Vect.IntArrayForm)
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Compute the sum of this polynomial and the given polynomial
        /// </summary>
        /// 
        /// <param name="Addend">he addend</param>
        /// 
        /// <returns>Return <c>this + a</c> (newly created)</returns>
        public PolynomialGF2mSmallM Add(PolynomialGF2mSmallM Addend)
        {
            int[] resultCoeff = Add(m_coefficients, Addend.m_coefficients, m_field);
            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the sum of this polynomial and the monomial of the given degree
        /// </summary>
        /// 
        /// <param name="Degree">The degree of the monomial</param>
        /// 
        /// <returns>Return <c>this + X^k</c></returns>
        public PolynomialGF2mSmallM AddMonomial(int Degree)
        {
            int[] monomial = new int[Degree + 1];
            monomial[Degree] = 1;
            int[] resultCoeff = Add(m_coefficients, monomial, m_field);

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Add the given polynomial to this polynomial (overwrite this).
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        public void AddToThis(PolynomialGF2mSmallM Addend)
        {
            m_coefficients = Add(m_coefficients, Addend.m_coefficients, m_field);
            ComputeDegree();
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Clear()
        {
            if (m_coefficients != null)
                Array.Clear(m_coefficients, 0, m_coefficients.Length);
            m_degree = 0;
            if (m_field != null)
                m_field.Clear();
        }

        /// <summary>
        /// Divide this polynomial by the given polynomial
        /// </summary>
        /// <param name="F">The polynomial</param>
        /// <returns>Returns polynomial pair = {q,r} where this = q*f+r and deg(r) &lt; deg(f)</returns>
        public PolynomialGF2mSmallM[] Divide(PolynomialGF2mSmallM F)
        {
            int[][] resultCoeffs = Divide(m_coefficients, F.m_coefficients, m_field);
            return new PolynomialGF2mSmallM[]{
            new PolynomialGF2mSmallM(m_field, resultCoeffs[0]),
            new PolynomialGF2mSmallM(m_field, resultCoeffs[1])};
        }

        /// <summary>
        /// Evaluate this polynomial <c>p</c> at a value <c>e</c> (in <c>GF(2^m)</c>) with the Horner scheme
        /// </summary>
        /// 
        /// <param name="E">The element of the finite field GF(2^m)</param>
        /// 
        /// <returns>Returns <c>this(e)</c></returns>
        public int EvaluateAt(int E)
        {
            int result = m_coefficients[m_degree];
            for (int i = m_degree - 1; i >= 0; i--)
                result = m_field.Multiply(result, E) ^ m_coefficients[i];
            
            return result;
        }

        /// <summary>
        /// Return the greatest common divisor of this and a polynomial <c>F</c>
        /// </summary>
        /// 
        /// <param name="F">The polynomial</param>
        /// 
        /// <returns>Returns Gcd(this, f)</returns>
        public PolynomialGF2mSmallM Gcd(PolynomialGF2mSmallM F)
        {
            int[] resultCoeff = Gcd(m_coefficients, F.m_coefficients, m_field);
            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Return the greatest common divisor of two polynomials over the field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="F">The first polynomial</param>
        /// <param name="G">The second polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns <c>Gcd(f, g)</c></returns>
        private static int[] Gcd(int[] F, int[] G, GF2mField GF2)
        {
            int[] a = F;
            int[] b = G;
            if (ComputeDegree(a) == -1)
                return b;

            while (ComputeDegree(b) != -1)
            {
                int[] c = Mod(a, b, GF2);
                a = new int[b.Length];
                Array.Copy(b, 0, a, 0, a.Length);
                b = new int[c.Length];
                Array.Copy(c, 0, b, 0, b.Length);
            }
            int coeff = GF2.Inverse(HeadCoefficient(a));

            return MultWithElement(a, coeff, GF2);
        }

        /// <summary>
        /// Returns the coefficient with the given index
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        /// 
        /// <returns>Returns the coefficient with the given index</returns>
        public int GetCoefficient(int Index)
        {
            if ((Index < 0) || (Index > m_degree))
                return 0;
            
            return m_coefficients[Index];
        }

        /// <summary>
        /// Returns encoded polynomial, i.e., this polynomial in byte array form
        /// </summary>
        /// 
        /// <returns>Returns the encoded polynomial</returns>
        public byte[] GetEncoded()
        {
            int d = 8;
            int count = 1;
            while (m_field.Degree > d)
            {
                count++;
                d += 8;
            }

            byte[] res = new byte[m_coefficients.Length * count];
            count = 0;
            for (int i = 0; i < m_coefficients.Length; i++)
            {
                for (int j = 0; j < d; j += 8)
                    res[count++] = (byte)(IntUtils.URShift(m_coefficients[i], j));
            }

            return res;
        }

        /// <summary>
        /// Reduce this polynomial modulo another polynomial
        /// </summary>
        /// 
        /// <param name="F">The reduction polynomial</param>
        /// 
        /// <returns>Returns <c>this mod f</c></returns>
        public PolynomialGF2mSmallM Mod(PolynomialGF2mSmallM F)
        {
            int[] resultCoeff = Mod(m_coefficients, F.m_coefficients, m_field);
            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the result of the division of this polynomial by another polynomial modulo a third polynomial
        /// </summary>
        /// 
        /// <param name="Divisor">The divisor</param>
        /// <param name="Modulus">The reduction polynomial</param>
        /// 
        /// <returns>Returns <c>this * divisor^(-1) mod modulus</c></returns>
        public PolynomialGF2mSmallM ModDivide(PolynomialGF2mSmallM Divisor, PolynomialGF2mSmallM Modulus)
        {
            int[] resultCoeff = ModDiv(m_coefficients, Divisor.m_coefficients, Modulus.m_coefficients, m_field);
            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the inverse of this polynomial modulo the given polynomial
        /// </summary>
        /// 
        /// <param name="A">The reduction polynomial</param>
        /// 
        /// <returns>Returns <c>this^(-1) mod a</c></returns>
        public PolynomialGF2mSmallM ModInverse(PolynomialGF2mSmallM A)
        {
            int[] unit = { 1 };
            int[] resultCoeff = ModDiv(unit, m_coefficients, A.m_coefficients, m_field);

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the product of this polynomial and another polynomial modulo a third polynomial
        /// </summary>
        /// 
        /// <param name="A">The polynomial</param>
        /// <param name="B">The reduction polynomial</param>
        /// 
        /// <returns>Returns <c>this * a mod b</c></returns>
        public PolynomialGF2mSmallM ModMultiply(PolynomialGF2mSmallM A, PolynomialGF2mSmallM B)
        {
            int[] resultCoeff = ModMultiply(m_coefficients, A.m_coefficients, B.m_coefficients, m_field);
            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute a polynomial pair (a,b) from this polynomial and the given
        /// polynomial g with the property b*this = a mod g and deg(a)&lt;=deg(g)/2
        /// </summary>
        /// 
        /// <param name="G">The reduction polynomial</param>
        /// 
        /// <returns>Returns PolynomialGF2mSmallM[] {a,b} with b*this = a mod g and deg(a)&lt;= deg(g)/2</returns>
        public PolynomialGF2mSmallM[] ModPolynomialToFracton(PolynomialGF2mSmallM G)
        {
            int dg = G.m_degree >> 1;
            int[] a0 = NormalForm(G.m_coefficients);
            int[] a1 = Mod(m_coefficients, G.m_coefficients, m_field);
            int[] b0 = { 0 };
            int[] b1 = { 1 };

            while (ComputeDegree(a1) > dg)
            {
                int[][] q = Divide(a0, a1, m_field);
                a0 = a1;
                a1 = q[1];
                int[] b2 = Add(b0, ModMultiply(q[0], b1, G.m_coefficients, m_field), m_field);
                b0 = b1;
                b1 = b2;
            }

            return new PolynomialGF2mSmallM[] { new PolynomialGF2mSmallM(m_field, a1), new PolynomialGF2mSmallM(m_field, b1) };
        }

        /// <summary>
        /// Square this polynomial using a squaring matrix
        /// </summary>
        /// 
        /// <param name="M">The squaring matrix</param>
        /// 
        /// <returns>Returns <c>this^2</c> modulo the reduction polynomial implicitly given via the squaring matrix</returns>
        public PolynomialGF2mSmallM ModSquareMatrix(PolynomialGF2mSmallM[] M)
        {
            int length = M.Length;
            int[] resultCoeff = new int[length];
            int[] thisSquare = new int[length];

            // square each entry of this polynomial
            for (int i = 0; i < m_coefficients.Length; i++)
                thisSquare[i] = m_field.Multiply(m_coefficients[i], m_coefficients[i]);

            // do matrix-vector multiplication
            for (int i = 0; i < length; i++)
            {
                // compute scalar product of i-th row and coefficient vector
                for (int j = 0; j < length; j++)
                {
                    if (i >= M[j].m_coefficients.Length)
                        continue;

                    int scalarTerm = m_field.Multiply(M[j].m_coefficients[i], thisSquare[j]);
                    resultCoeff[i] = m_field.Add(resultCoeff[i], scalarTerm);
                }
            }

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the square root of this polynomial modulo the given polynomial
        /// </summary>
        /// 
        /// <param name="A">The reduction polynomial</param>
        /// 
        /// <returns>Returns <c>this^(1/2) mod A</c></returns>
        public PolynomialGF2mSmallM ModSquareRoot(PolynomialGF2mSmallM A)
        {
            int[] resultCoeff = IntUtils.DeepCopy(m_coefficients);
            int[] help = ModMultiply(resultCoeff, resultCoeff, A.m_coefficients, m_field);

            while (!IsEqual(help, m_coefficients))
            {
                resultCoeff = NormalForm(help);
                help = ModMultiply(resultCoeff, resultCoeff, A.m_coefficients, m_field);
            }

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the square root of this polynomial using a square root matrix
        /// </summary>
        /// 
        /// <param name="M">The matrix for computing square roots in <c>(GF(2^m))^t</c> the polynomial ring defining the square root matrix</param>
        /// 
        /// <returns>Returns <c>this^(1/2)</c> modulo the reduction polynomial implicitly given via the square root matrix</returns>
        public PolynomialGF2mSmallM ModSquareRootMatrix(PolynomialGF2mSmallM[] M)
        {
            int length = M.Length;
            int[] resultCoeff = new int[length];

            // do matrix multiplication
            for (int i = 0; i < length; i++)
            {
                // compute scalar product of i-th row and j-th column
                for (int j = 0; j < length; j++)
                {
                    if (i >= M[j].m_coefficients.Length)
                        continue;

                    if (j < m_coefficients.Length)
                    {
                        int scalarTerm = m_field.Multiply(M[j].m_coefficients[i], m_coefficients[j]);
                        resultCoeff[i] = m_field.Add(resultCoeff[i], scalarTerm);
                    }
                }
            }

            // compute the square root of each entry of the result coefficients
            for (int i = 0; i < length; i++)
                resultCoeff[i] = m_field.Sqrt(resultCoeff[i]);

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the product of this polynomial and the given factor using a Karatzuba like scheme
        /// </summary>
        /// 
        /// <param name="Factor">the polynomial factor</param>
        /// 
        /// <returns>Returns <c>this * factor</c></returns>
        public PolynomialGF2mSmallM Multiply(PolynomialGF2mSmallM Factor)
        {
            int[] resultCoeff = Multiply(m_coefficients, Factor.m_coefficients, m_field);

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Compute the product of this polynomial with an element from GF(2^m)
        /// </summary>
        /// 
        /// <param name="Element">An element of the finite field GF(2^m)</param>
        /// 
        /// <returns>Return <c>this * element</c> (newly created)</returns>
        public PolynomialGF2mSmallM MultWithElement(int Element)
        {
            if (!m_field.IsElementOfThisField(Element))
                throw new ArithmeticException("Not an element of the finite field this polynomial is defined over.");

            int[] resultCoeff = MultWithElement(m_coefficients, Element, m_field);

            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }

        /// <summary>
        /// Multiply this polynomial with an element from GF(2^m)
        /// </summary>
        /// 
        /// <param name="Element">An element of the finite field GF(2^m)</param>
        public void MultThisWithElement(int Element)
        {
            if (!m_field.IsElementOfThisField(Element))
                throw new ArithmeticException("Not an element of the finite field this polynomial is defined over.");

            m_coefficients = MultWithElement(m_coefficients, Element, m_field);
            ComputeDegree();
        }

        /// <summary>
        /// Compute the product of a polynomial a with an element from the finite field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="A">The polynomial</param>
        /// <param name="Element">An element of the finite field GF(2^m)</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Return <c>a * element</c></returns>
        private static int[] MultWithElement(int[] A, int Element, GF2mField GF2)
        {
            int degree = ComputeDegree(A);
            if (degree == -1 || Element == 0)
                return new int[1];

            if (Element == 1)
                return IntUtils.DeepCopy(A);

            int[] result = new int[degree + 1];
            for (int i = degree; i >= 0; i--)
                result[i] = GF2.Multiply(A[i], Element);

            return result;
        }

        /// <summary>
        /// Compute the product of this polynomial with a monomial X^k
        /// </summary>
        /// 
        /// <param name="K">The degree of the monomial</param>
        /// 
        /// <returns>Return <c>this * X^k</c></returns>
        public PolynomialGF2mSmallM MultWithMonomial(int K)
        {
            int[] resultCoeff = MultWithMonomial(m_coefficients, K);
            return new PolynomialGF2mSmallM(m_field, resultCoeff);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compare this element with another object
        /// </summary>
        /// 
        /// <param name="Obj">The object for comprison</param>
        /// 
        /// <returns>Returns <c>true</c> if the two objects are equal, <c>false</c> otherwise</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is PolynomialGF2mSmallM))
                return false;

            PolynomialGF2mSmallM p = (PolynomialGF2mSmallM)Obj;

            if ((m_field.Equals(p.m_field)) && (m_degree.Equals(p.m_degree)) && (Compare.IsEqual(m_coefficients, p.m_coefficients)))
                return true;

            return false;
        }

        /// <summary>
        /// Returns the hash code of this element
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = m_field.GetHashCode();
            hash += ArrayUtils.GetHashCode(m_coefficients);
            
            return hash;
        }

        /// <summary>
        /// Returns a human readable form of the polynomial
        /// </summary>
        /// 
        /// <returns>Returns a human readable form of the polynomial</returns>
        public override String ToString()
        {
            String str = " Polynomial over " + m_field.ToString() + ": \n";

            for (int i = 0; i < m_coefficients.Length; i++)
                str = str + m_field.ElementToString(m_coefficients[i]) + "Y^" + i + "+";
            
            str = str + ";";

            return str;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Compute the sum of two polynomials a and b over the finite field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="B">The second polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Return a + b</returns>
        private static int[] Add(int[] A, int[] B, GF2mField GF2)
        {
            int[] result, addend;
            if (A.Length < B.Length)
            {
                result = new int[B.Length];
                Array.Copy(B, 0, result, 0, B.Length);
                addend = A;
            }
            else
            {
                result = new int[A.Length];
                Array.Copy(A, 0, result, 0, A.Length);
                addend = B;
            }

            for (int i = addend.Length - 1; i >= 0; i--)
                result[i] = GF2.Add(result[i], addend[i]);

            return result;
        }

        /// <summary>
        /// Compute the degree of this polynomial. If this is the zero polynomial, the degree is -1
        /// </summary>
        private void ComputeDegree()
        {
            for (m_degree = m_coefficients.Length - 1; m_degree >= 0 && m_coefficients[m_degree] == 0; m_degree--)
                { ; }
        }

        /// <summary>
        /// Compute the degree of a polynomial
        /// </summary>
        /// 
        /// <param name="A">The polynomial</param>
        /// 
        /// <returns>Returns the degree of the polynomial <c>a</c>. If <c>a</c> is the zero polynomial, return -1</returns>
        private static int ComputeDegree(int[] A)
        {
            int degree;
            for (degree = A.Length - 1; degree >= 0 && A[degree] == 0; degree--)
                { ; }
            return degree;
        }

        /// <summary>
        /// Create an irreducible polynomial with the given degree over the field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="Degree">The polynomial degree</param>
        /// <param name="SecRnd">The source of randomness</param>
        /// 
        /// <returns>he generated irreducible polynomial</returns>
        private int[] CreateRandomIrreduciblePolynomial(int Degree, IRandom SecRnd)
        {
            int[] resCoeff = new int[Degree + 1];
            int[] resTemp = new int[Degree + 1];

            resCoeff[Degree] = 1;
            resCoeff[0] = m_field.GetRandomNonZeroElement(SecRnd);

            if (ParallelUtils.IsParallel)
            {
                Parallel.For(0, Degree, i =>
                    resCoeff[i] = GetRandomElement(SecRnd, m_field));
            }
            else
            {
                for (int i = 1; i < Degree; i++)
                    resCoeff[i] = GetRandomElement(SecRnd, m_field);
            }

            while (!IsIrreducible(resCoeff, m_field))
            {
                int n = RandomDegree.NextInt(SecRnd, Degree);

                if (n != 0)
                    resCoeff[n] = GetRandomElement(SecRnd, m_field);
                else
                    resCoeff[0] = m_field.GetRandomNonZeroElement(SecRnd);
            }

            return resCoeff;
        }

        /// <summary>
        /// Get a randome element over degree Gf2
        /// </summary>
        /// 
        /// <param name="SecRnd">The source of randomness</param>
        /// <param name="GFM">The Gf2 field</param>
        /// 
        /// <returns>A random element</returns>
        private static int GetRandomElement(IRandom SecRnd, GF2mField GFM)
        {
            return RandomDegree.NextInt(SecRnd, 1 << GFM.Degree);
        }

        /// <summary>
        /// Compute the result of the division of two polynomials over the field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="F">The second polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns <c>int[][] {q,r}</c>, where <c>a = q*f+r</c> and <c>deg(r) &lt; deg(f)</c></returns>
        private static int[][] Divide(int[] A, int[] F, GF2mField GF2)
        {
            int df = ComputeDegree(F);
            int da = ComputeDegree(A) + 1;
            if (df == -1)
                throw new ArithmeticException("Division by zero.");

            int[][] result = new int[2][];
            result[0] = new int[1];
            result[1] = new int[da];
            int hc = HeadCoefficient(F);
            hc = GF2.Inverse(hc);
            result[0][0] = 0;
            Array.Copy(A, 0, result[1], 0, result[1].Length);

            while (df <= ComputeDegree(result[1]))
            {
                int[] q;
                int[] coeff = new int[1];
                coeff[0] = GF2.Multiply(HeadCoefficient(result[1]), hc);
                q = MultWithElement(F, coeff[0], GF2);
                int n = ComputeDegree(result[1]) - df;
                q = MultWithMonomial(q, n);
                coeff = MultWithMonomial(coeff, n);
                result[0] = Add(coeff, result[0], GF2);
                result[1] = Add(q, result[1], GF2);
            }

            return result;
        }

        /// <summary>
        /// Compare two polynomials given as int arrays
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="B">The second polynomial</param>
        /// 
        /// <returns>Returns <c>true</c> if <c>a</c> and <c>b</c> represent the same polynomials, <c>false</c> otherwise</returns>
        private static bool IsEqual(int[] A, int[] B)
        {
            int da = ComputeDegree(A);
            int db = ComputeDegree(B);
            if (da != db)
                return false;

            for (int i = 0; i <= da; i++)
            {
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Return the head coefficient of a polynomial
        /// </summary>
        /// 
        /// <param name="A">he polynomial</param>
        /// 
        /// <returns>Returns the head coefficient of <c>A</c></returns>
        private static int HeadCoefficient(int[] A)
        {
            int degree = ComputeDegree(A);
            if (degree == -1)
                return 0;
            
            return A[degree];
        }

        /// <summary>
        /// Check a polynomial for irreducibility over the field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="A">The polynomial to check</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns true if a is irreducible, false otherwise</returns>
        private static bool IsIrreducible(int[] A, GF2mField GF2)
        {
            if (A[0] == 0)
                return false;

            bool state = true;
            int d = ComputeDegree(A) >> 1;
            int[] u = { 0, 1 };
            int[] Y = { 0, 1 };
            int fieldDegree = GF2.Degree;

            if (ParallelUtils.IsParallel)
            {
                CancellationTokenSource cts = new CancellationTokenSource();
                ParallelOptions options = new ParallelOptions();
                options.MaxDegreeOfParallelism = Environment.ProcessorCount;
                options.CancellationToken = cts.Token;
                options.CancellationToken.ThrowIfCancellationRequested();

                try
                {
                    Parallel.For(0, d, options, loopState =>
                    {
                        if (!cts.IsCancellationRequested)
                        {
                            for (int j = fieldDegree - 1; j >= 0; j--)
                                u = ModMultiply(u, u, A, GF2);

                            u = NormalForm(u);
                            int[] g = Gcd(Add(u, Y, GF2), A, GF2);

                            if (ComputeDegree(g) != 0)
                            {
                                state = false;
                                cts.Cancel();
                            }
                        }
                    });
                }
                catch { }
            }
            else
            {
                for (int i = 0; i < d; i++)
                {
                    for (int j = fieldDegree - 1; j >= 0; j--)
                        u = ModMultiply(u, u, A, GF2);

                    u = NormalForm(u);
                    int[] g = Gcd(Add(u, Y, GF2), A, GF2);

                    if (ComputeDegree(g) != 0)
                        state = false;
                }
            }

            return state;
        }

        /// <summary>
        /// Reduce a polynomial modulo another polynomial
        /// </summary>
        /// 
        /// <param name="A">The polynomial</param>
        /// <param name="F">The reduction polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns <c>a mod f</c></returns>
        private static int[] Mod(int[] A, int[] F, GF2mField GF2)
        {
            int df = ComputeDegree(F);
            if (df == -1)
                throw new ArithmeticException("Division by zero");

            int[] result = new int[A.Length];
            int hc = HeadCoefficient(F);
            hc = GF2.Inverse(hc);
            Array.Copy(A, 0, result, 0, result.Length);
            while (df <= ComputeDegree(result))
            {
                int[] q;
                int coeff = GF2.Multiply(HeadCoefficient(result), hc);
                q = MultWithMonomial(F, ComputeDegree(result) - df);
                q = MultWithElement(q, coeff, GF2);
                result = Add(q, result, GF2);
            }

            return result;
        }

        /// <summary>
        /// Compute the result of the division of two polynomials modulo a third polynomial over the field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="B">The second polynomial</param>
        /// <param name="G">The reduction polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns <c>a * b^(-1) mod g</c></returns>
        private static int[] ModDiv(int[] A, int[] B, int[] G, GF2mField GF2)
        {
            int[] r0 = NormalForm(G);
            int[] r1 = Mod(B, G, GF2);
            int[] s0 = { 0 };
            int[] s1 = Mod(A, G, GF2);
            int[] s2;
            int[][] q;

            while (ComputeDegree(r1) != -1)
            {
                q = Divide(r0, r1, GF2);
                r0 = NormalForm(r1);
                r1 = NormalForm(q[1]);
                s2 = Add(s0, ModMultiply(q[0], s1, G, GF2), GF2);
                s0 = NormalForm(s1);
                s1 = NormalForm(s2);
            }
            int hc = HeadCoefficient(r0);
            s0 = MultWithElement(s0, GF2.Inverse(hc), GF2);

            return s0;
        }

        /// <summary>
        /// Compute the product of two polynomials modulo a third polynomial over the finite field <c>GF(2^m)</c>
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="B">The second polynomial</param>
        /// <param name="G">The reduction polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns <c>a * b mod g</c></returns>
        private static int[] ModMultiply(int[] A, int[] B, int[] G, GF2mField GF2)
        {
            return Mod(Multiply(A, B, GF2), G, GF2);
        }

        /// <summary>
        /// Compute the product of two polynomials over the field <c>GF(2^m)</c> using a Karatzuba like multiplication
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="B">The second polynomial</param>
        /// <param name="GF2">The GF2 field</param>
        /// 
        /// <returns>Returns <c>a * b</c></returns>
        private static int[] Multiply(int[] A, int[] B, GF2mField GF2)
        {
            int[] mult1, mult2;
            if (ComputeDegree(A) < ComputeDegree(B))
            {
                mult1 = B;
                mult2 = A;
            }
            else
            {
                mult1 = A;
                mult2 = B;
            }

            mult1 = NormalForm(mult1);
            mult2 = NormalForm(mult2);

            if (mult2.Length == 1)
                return MultWithElement(mult1, mult2[0], GF2);

            int d1 = mult1.Length;
            int d2 = mult2.Length;
            int[] result = new int[d1 + d2 - 1];

            if (d2 != d1)
            {
                int[] res1 = new int[d2];
                int[] res2 = new int[d1 - d2];
                Array.Copy(mult1, 0, res1, 0, res1.Length);
                Array.Copy(mult1, d2, res2, 0, res2.Length);
                res1 = Multiply(res1, mult2, GF2);
                res2 = Multiply(res2, mult2, GF2);
                res2 = MultWithMonomial(res2, d2);
                result = Add(res1, res2, GF2);
            }
            else
            {
                d2 = IntUtils.URShift((d1 + 1), 1);
                int d = d1 - d2;
                int[] firstPartMult1 = new int[d2];
                int[] firstPartMult2 = new int[d2];
                int[] secondPartMult1 = new int[d];
                int[] secondPartMult2 = new int[d];
                Array.Copy(mult1, 0, firstPartMult1, 0, firstPartMult1.Length);
                Array.Copy(mult1, d2, secondPartMult1, 0, secondPartMult1.Length);
                Array.Copy(mult2, 0, firstPartMult2, 0, firstPartMult2.Length);
                Array.Copy(mult2, d2, secondPartMult2, 0, secondPartMult2.Length);
                int[] helpPoly1 = Add(firstPartMult1, secondPartMult1, GF2);
                int[] helpPoly2 = Add(firstPartMult2, secondPartMult2, GF2);
                int[] res1 = Multiply(firstPartMult1, firstPartMult2, GF2);
                int[] res2 = Multiply(helpPoly1, helpPoly2, GF2);
                int[] res3 = Multiply(secondPartMult1, secondPartMult2, GF2);
                res2 = Add(res2, res1, GF2);
                res2 = Add(res2, res3, GF2);
                res3 = MultWithMonomial(res3, d2);
                result = Add(res2, res3, GF2);
                result = MultWithMonomial(result, d2);
                result = Add(result, res1, GF2);
            }

            return result;
        }

        /// <summary>
        /// Compute the product of a polynomial with a monomial X^k
        /// </summary>
        /// <param name="A">The polynomial</param>
        /// <param name="K">The degree of the monomial</param>
        /// <returns>Return <c>a * X^k</c></returns>
        private static int[] MultWithMonomial(int[] A, int K)
        {
            int d = ComputeDegree(A);
            if (d == -1)
                return new int[1];
            
            int[] result = new int[d + K + 1];
            Array.Copy(A, 0, result, K, d + 1);

            return result;
        }

        /// <summary>
        /// Strip leading zero coefficients from the given polynomial
        /// </summary>
        /// 
        /// <param name="A">The polynomial</param>
        /// 
        /// <returns>The reduced polynomial</returns>
        private static int[] NormalForm(int[] A)
        {
            int d = ComputeDegree(A);

            // if a is the zero polynomial
            if (d == -1)
                return new int[1];

            // if a already is in normal form
            if (A.Length == d + 1)
                return IntUtils.DeepCopy(A);

            // else, reduce a
            int[] result = new int[d + 1];
            Array.Copy(A, 0, result, 0, d + 1);

            return result;
        }
        #endregion
    }
}
