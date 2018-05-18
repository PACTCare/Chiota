#region Directives
using System;
using System.Collections.Generic;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements the abstract class <c>GF2nField</c> for ONB representation.
    /// <para>It computes the fieldpolynomial, multiplication matrix and one of its roots mONBRoot,
    /// (see for example <a href="http://www2.certicom.com/ecc/intro.htm">Certicoms Whitepapers</a>).
    /// GF2nField is used by GF2nONBElement which implements the elements of this field.</para>
    /// </summary>
    internal sealed class GF2nONBField : GF2nField
    {
        #region Constants
        private const int MAXLONG = 64;
        #endregion

        #region Fields
        // holds the number of relevant bits in mONBPol[mLength-1].
        private int m_Bit;
        // holds the length of the array-representation of degree m_Degree.
        private int m_Length;
        // holds the type of mONB
        private int m_Type;
        // holds the multiplication matrix
        public int[][] m_MultM;
        private IRandom m_secRand;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs an instance of the finite field with 2^degree elements and characteristic 2
        /// </summary>
        /// 
        /// <param name="Degree">The extention degree of this field</param>
        /// <param name="Rand">The prng instance</param>
        public GF2nONBField(int Degree, IRandom Rand)
        {
            if (Degree < 3)
                throw new ArgumentException("k must be at least 3");

            m_secRand = Rand;
            DegreeN = Degree;
            m_Length = DegreeN / MAXLONG;
            m_Bit = DegreeN & (MAXLONG - 1);
            if (m_Bit == 0)
                m_Bit = MAXLONG;
            else
                m_Length++;

            ComputeType();

            // only ONB-implementations for type 1 and type 2
            if (m_Type < 3)
            {
                m_MultM = ArrayUtils.CreateJagged<int[][]>(DegreeN, 2);
                for (int i = 0; i < DegreeN; i++)
                {
                    m_MultM[i][0] = -1;
                    m_MultM[i][1] = -1;
                }
                ComputeMultMatrix();
            }
            else
            {
                throw new Exception("\nThe type of this field is " + m_Type);
            }
            ComputeFieldPolynomial();
            Fields = new List<GF2nField>();
            Matrices = new List<GF2Polynomial[]>();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the number of relevant bits in mONBPol[mLength-1]
        /// </summary>
        /// 
        /// <returns>The relevant bits count</returns>
        public int GetONBBit()
        {
            return m_Bit;
        }

        /// <summary>
        /// Get the length of the array-representation of degree
        /// </summary>
        /// 
        /// <returns>The length</returns>
        public int GetONBLength()
        {
            return m_Length;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Computes the change-of-basis matrix for basis conversion according to 1363.
        /// The result is stored in the lists fields and matrices.
        /// </summary>
        /// 
        /// <param name="B1">The GF2nField to convert to</param>
        public override void ComputeCOBMatrix(GF2nField B1)
        {
            // we are in B0 here!
            if (DegreeN != B1.Degree)
                throw new ArgumentException("GF2nField.computeCOBMatrix: B1 has a different degree and thus cannot be coverted to!");
            
            int i, j;
            GF2nElement[] gamma;
            GF2nElement u;
            GF2Polynomial[] COBMatrix = new GF2Polynomial[DegreeN];
            for (i = 0; i < DegreeN; i++)
                COBMatrix[i] = new GF2Polynomial(DegreeN);

            // find Random Root
            do
            {
                // u is in representation according to B1
                u = B1.RandomRoot(FieldPoly);
            }
            while (u.IsZero());

            gamma = new GF2nPolynomialElement[DegreeN];
            // build gamma matrix by squaring
            gamma[0] = (GF2nElement)u.Clone();
            for (i = 1; i < DegreeN; i++)
                gamma[i] = gamma[i - 1].Square();
            
            // convert horizontal gamma matrix by vertical Bitstrings
            for (i = 0; i < DegreeN; i++)
            {
                for (j = 0; j < DegreeN; j++)
                {
                    if (gamma[i].TestBit(j))
                        COBMatrix[DegreeN - j - 1].SetBit(DegreeN - i - 1);
                }
            }

            Fields.Add(B1);
            Matrices.Add(COBMatrix);
            B1.Fields.Add(this);
            B1.Matrices.Add(InvertMatrix(COBMatrix));
        }

        /// <summary>
        /// Computes the field polynomial for a ONB according to IEEE 1363 A.7.2
        /// </summary>
        protected override void ComputeFieldPolynomial()
        {
            if (m_Type == 1)
            {
                FieldPoly = new GF2Polynomial(DegreeN + 1, "ALL");
            }
            else if (m_Type == 2)
            {
                // 1. q = 1
                GF2Polynomial q = new GF2Polynomial(DegreeN + 1, "ONE");
                // 2. p = t+1
                GF2Polynomial p = new GF2Polynomial(DegreeN + 1, "X");
                p.AddToThis(q);
                GF2Polynomial r;
                int i;
                // 3. for i = 1 to (m-1) do
                for (i = 1; i < DegreeN; i++)
                {
                    // r <- q
                    r = q;
                    // q <- p
                    q = p;
                    // p = tq+r
                    p = q.ShiftLeft();
                    p.AddToThis(r);
                }
                FieldPoly = p;
            }
        }

        /// <summary>
        /// Computes a random root of the given polynomial
        /// </summary>
        /// 
        /// <param name="P">A polynomial</param>
        /// 
        /// <returns>A random root of the polynomial</returns>
        public override GF2nElement RandomRoot(GF2Polynomial P)
        {
            // We are in B1!!!
            GF2nPolynomial c;
            GF2nPolynomial ut;
            GF2nElement u;
            GF2nPolynomial h;
            int hDegree;
            // 1. Set g(t) <- f(t)
            GF2nPolynomial g = new GF2nPolynomial(P, this);
            int gDegree = g.Degree;
            int i;

            // 2. while deg(g) > 1
            while (gDegree > 1)
            {
                do
                {
                    // 2.1 choose random u (element of) GF(2^m)
                    u = new GF2nONBElement(this, m_secRand);
                    ut = new GF2nPolynomial(2, GF2nONBElement.Zero(this));
                    // 2.2 Set c(t) <- ut
                    ut.Set(1, u);
                    c = new GF2nPolynomial(ut);
                    // 2.3 For i from 1 to m-1 do
                    for (i = 1; i <= DegreeN - 1; i++)
                    {
                        // 2.3.1 c(t) <- (c(t)^2 + ut) mod g(t)
                        c = c.MultiplyAndReduce(c, g);
                        c = c.Add(ut);
                    }
                    // 2.4 set h(t) <- GCD(c(t), g(t))
                    h = c.Gcd(g);
                    // 2.5 if h(t) is constant or deg(g) = deg(h) then go to
                    // step 2.1
                    hDegree = h.Degree;
                    gDegree = g.Degree;
                } 
                while ((hDegree == 0) || (hDegree == gDegree));

                // 2.6 If 2deg(h) > deg(g) then set g(t) <- g(t)/h(t) ...
                if ((hDegree << 1) > gDegree)
                    g = g.Quotient(h);
                else // ... else g(t) <- h(t)
                    g = new GF2nPolynomial(h);
                
                gDegree = g.Degree;
            }
            // 3. Output g(0)
            return g.At(0);

        }
        #endregion

        #region Private Methods
        private void ComputeType()
        {
            if ((DegreeN & 7) == 0)
                throw new Exception("The extension degree is divisible by 8!");
            
            // checking for the type
            int s = 0;
            int k = 0;
            m_Type = 1;

            for (int d = 0; d != 1; m_Type++)
            {
                s = m_Type * DegreeN + 1;
                if (BigMath.IsPrime(s))
                {
                    k = BigMath.Order(2, s);
                    d = BigMath.Gcd(m_Type * DegreeN / k, DegreeN);
                }
            }
            m_Type--;

            if (m_Type == 1)
            {
                s = (DegreeN << 1) + 1;
                if (BigMath.IsPrime(s))
                {
                    k = BigMath.Order(2, s);
                    int d = BigMath.Gcd((DegreeN << 1) / k, DegreeN);
                    if (d == 1)
                        m_Type++;
                }
            }
        }

        private void ComputeMultMatrix()
        {
            if ((m_Type & 7) != 0)
            {
                int p = m_Type * DegreeN + 1;
                // compute sequence F[1] ... F[p-1] via A.3.7. of 1363.
                // F[0] will not be filled!
                int[] F = new int[p];
                int u;

                if (m_Type == 1)
                    u = 1;
                else if (m_Type == 2)
                    u = p - 1;
                else
                    u = ElementOfOrder(m_Type, p);

                int w = 1;
                int n;
                for (int j = 0; j < m_Type; j++)
                {
                    n = w;

                    for (int i = 0; i < DegreeN; i++)
                    {
                        F[n] = i;
                        n = (n << 1) % p;
                        if (n < 0)
                            n += p;
                    }

                    w = u * w % p;
                    if (w < 0)
                        w += p;
                }

                // building the matrix (m_Degree * 2)
                if (m_Type == 1)
                {
                    for (int k = 1; k < p - 1; k++)
                    {
                        if (m_MultM[F[k + 1]][0] == -1)
                            m_MultM[F[k + 1]][0] = F[p - k];
                        else
                            m_MultM[F[k + 1]][1] = F[p - k];
                    }

                    int m_2 = DegreeN >> 1;
                    for (int k = 1; k <= m_2; k++)
                    {

                        if (m_MultM[k - 1][0] == -1)
                            m_MultM[k - 1][0] = m_2 + k - 1;
                        else
                            m_MultM[k - 1][1] = m_2 + k - 1;

                        if (m_MultM[m_2 + k - 1][0] == -1)
                            m_MultM[m_2 + k - 1][0] = k - 1;
                        else
                            m_MultM[m_2 + k - 1][1] = k - 1;
                    }
                }
                else if (m_Type == 2)
                {
                    for (int k = 1; k < p - 1; k++)
                    {
                        if (m_MultM[F[k + 1]][0] == -1)
                            m_MultM[F[k + 1]][0] = F[p - k];
                        else
                            m_MultM[F[k + 1]][1] = F[p - k];
                    }
                }
                else
                {
                    throw new Exception("only type 1 or type 2 implemented");
                }
            }
            else
            {
                throw new Exception("bisher nur fuer Gausssche Normalbasen" + " implementiert");
            }
        }

        private int ElementOfOrder(int K, int P)
        {
            Random random = new Random();
            int m = 0;

            while (m == 0)
            {
                m = random.Next();
                m %= P - 1;
                if (m < 0)
                    m += P - 1;
            }

            int l = BigMath.Order(m, P);

            while (l % K != 0 || l == 0)
            {
                while (m == 0)
                {
                    m = random.Next();
                    m %= P - 1;
                    if (m < 0)
                        m += P - 1;
                }
                l = BigMath.Order(m, P);
            }

            int r = m;
            l = K / l;

            for (int i = 2; i <= l; i++)
                r *= m;

            return r;
        }

        /// <summary>
        /// Compute the inverse of a matrix <c>A</c>
        /// </summary>
        /// 
        /// <param name="A">The matrix</param>
        /// 
        /// <returns>Returns <c>A^-1</c></returns>
        private int[][] InvMatrix(int[][] A)
        {
            int[][] b = ArrayUtils.CreateJagged<int[][]>(DegreeN, DegreeN);
            b = A;
            int[][] inv = ArrayUtils.CreateJagged<int[][]>(DegreeN, DegreeN);

            for (int i = 0; i < DegreeN; i++)
                inv[i][i] = 1;

            for (int i = 0; i < DegreeN; i++)
            {
                for (int j = i; j < DegreeN; j++)
                    b[DegreeN - 1 - i][j] = b[i][i];
            }
            return b;
        }
        #endregion
    }
}
