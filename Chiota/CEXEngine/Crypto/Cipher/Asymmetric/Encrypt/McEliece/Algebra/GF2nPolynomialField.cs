#region Directives
using System;
using System.Collections;
using System.Collections.Generic;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements the abstract class <c>GF2nField</c> for polynomial representation.
    /// <para>It computes the field polynomial and the squaring matrix.
    /// GF2nField is used by GF2nPolynomialElement which implements the elements of this field.</para>
    /// </summary>
    internal class GF2nPolynomialField : GF2nField
    {
        #region Fields
        // Matrix used for fast squaring
        private GF2Polynomial[] m_squaringMatrix;
        // field polynomial is a trinomial
        private bool m_isTrinomial = false;
        // field polynomial is a pentanomial
        private bool m_isPentanomial = false;
        // middle coefficient of the field polynomial in case it is a trinomial
        private int m_tc;
        // middle 3 coefficients of the field polynomial in case it is a pentanomial
        private int[] m_pc = new int[3];
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns true if the field polynomial is a pentanomial; the coefficients can be retrieved using Pc property
        /// </summary>
        public bool IsPentanomial
        {
            get { return m_isPentanomial; }
        }

        /// <summary>
        /// Get: Returns true if the field polynomial is a trinomial; the coefficient can be retrieved using Tc property
        /// </summary>
        public bool IsTrinomial
        {
            get { return m_isTrinomial; }
        }

        /// <summary>
        /// Get: Returns the degree of the middle coefficients of the used field pentanomial (x^n + x^(Pc[2]) + x^(Pc[1]) + x^(Pc[0]) + 1)
        /// </summary>
        public int[] Pc
        {
            get
            {
                if (!m_isPentanomial)
                    throw new Exception();

                int[] result = new int[3];
                Array.Copy(m_pc, 0, result, 0, 3);

                return result;
            }
        }

        /// <summary>
        /// Get: Matrix used for fast squaring of GF2Polynomial
        /// </summary>
        public GF2Polynomial[] SquaringMatrix
        {
            get { return m_squaringMatrix; }
        }

        /// <summary>
        /// Get: Returns the degree of the middle coefficient of the used field trinomial (x^n + x^(getTc()) + 1)
        /// </summary>
        public int Tc
        {
            get
            {
                if (!m_isTrinomial)
                    throw new Exception();

                return m_tc;
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs an instance of the finite field with 2^Degree elements and characteristic 2
        /// </summary>
        /// 
        /// <param name="Degree">The extention degree of this field</param>
        public GF2nPolynomialField(int Degree)
        {
            if (Degree < 3)
                throw new ArgumentException("GF2nPolynomialField: Degree must be at least 3");
            
            DegreeN = Degree;
            ComputeFieldPolynomial();
            ComputeSquaringMatrix();
            Fields = new List<GF2nField>();
            Matrices = new List<GF2Polynomial[]>();
        }

        /// <summary>
        /// Constructs an instance of the finite field with 2^Degree elements and characteristic 2
        /// </summary>
        /// 
        /// <param name="Degree">he degree of this field</param>
        /// <param name="File">True if you want to read the field polynomial from the file,
        /// false if you want to use a random fielpolynomial (this can take very long for huge degrees)</param>
        public GF2nPolynomialField(int Degree, bool File)
        {
            if (Degree < 3)
                throw new ArgumentException("k must be at least 3");

            DegreeN = Degree;
            if (File)
                ComputeFieldPolynomial();
            else
                ComputeFieldPolynomial2();
            
            ComputeSquaringMatrix();
            Fields = new List<GF2nField>();
            Matrices = new List<GF2Polynomial[]>();
        }

        /// <summary>
        /// Creates a new GF2nField of degree <c>i</c> and uses the given <c>G</c> as field polynomial. 
        /// <para>The <c>G</c> is checked whether it is irreducible. This can take some time if <c>Degree</c> is huge!</para>
        /// </summary>
        /// 
        /// <param name="Degree">The degree of the GF2nField</param>
        /// <param name="G">The field polynomial to use</param>
        public GF2nPolynomialField(int Degree, GF2Polynomial G)
        {
            if (Degree < 3)
                throw new ArgumentException("degree must be at least 3");
            if (G.Length != Degree + 1)
                throw new Exception();
            if (!G.IsIrreducible())
                throw new Exception();
            
            DegreeN = Degree;
            // fieldPolynomial = new Bitstring(polynomial);
            FieldPoly = G;
            ComputeSquaringMatrix();
            int k = 2; // check if the polynomial is a trinomial or pentanomial
            for (int j = 1; j < FieldPoly.Length - 1; j++)
            {
                if (FieldPoly.TestBit(j))
                {
                    k++;
                    if (k == 3)
                        m_tc = j;
                    if (k <= 5)
                        m_pc[k - 3] = j;
                }
            }
            if (k == 3)
                m_isTrinomial = true;
            if (k == 5)
                m_isPentanomial = true;

            Fields = new List<GF2nField>();
            Matrices = new List<GF2Polynomial[]>();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns row vector <c>Index</c> of the squaring matrix
        /// </summary>
        /// 
        /// <param name="Index">The index of the row vector to return</param>
        /// 
        /// <returns>Returns a copy of SquaringMatrix[i]</returns>
        public GF2Polynomial SquaringVector(int Index)
        {
            return new GF2Polynomial(m_squaringMatrix[Index]);
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
                throw new ArgumentException("GF2nPolynomialField.computeCOBMatrix: B1 has a different degree and thus cannot be coverted to!");
            
            if (B1 is GF2nONBField)
            {
                // speedup (calculation is done in PolynomialElements instead of ONB)
                B1.ComputeCOBMatrix(this);
                return;
            }

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

            // build gamma matrix by multiplying by u
            if (u is GF2nONBElement)
            {
                gamma = new GF2nONBElement[DegreeN];
                gamma[DegreeN - 1] = GF2nONBElement.One((GF2nONBField)B1);
            }
            else
            {
                gamma = new GF2nPolynomialElement[DegreeN];
                gamma[DegreeN - 1] = GF2nPolynomialElement.One((GF2nPolynomialField)B1);
            }
            gamma[DegreeN - 2] = u;
            for (i = DegreeN - 3; i >= 0; i--)
                gamma[i] = (GF2nElement)gamma[i + 1].Multiply(u);
            
            if (B1 is GF2nONBField)
            {
                // convert horizontal gamma matrix by vertical Bitstrings
                for (i = 0; i < DegreeN; i++)
                {
                    for (j = 0; j < DegreeN; j++)
                    {
                        // TODO remember: ONB treats its Bits in reverse order !!!
                        if (gamma[i].TestBit(DegreeN - j - 1))
                            COBMatrix[DegreeN - j - 1].SetBit(DegreeN - i - 1);
                    }
                }
            }
            else
            {
                // convert horizontal gamma matrix by vertical Bitstrings
                for (i = 0; i < DegreeN; i++)
                {
                    for (j = 0; j < DegreeN; j++)
                    {
                        if (gamma[i].TestBit(j))
                            COBMatrix[DegreeN - j - 1].SetBit(DegreeN - i - 1);
                    }
                }
            }

            // store field and matrix for further use
            Fields.Add(B1);
            Matrices.Add(COBMatrix);
            // store field and inverse matrix for further use in B1
            B1.Fields.Add(this);
            B1.Matrices.Add(InvertMatrix(COBMatrix));
        }

        /// <summary>
        /// Computes the field polynomial. This can take a long time for big degrees.
        /// </summary>
        protected override void ComputeFieldPolynomial()
        {
            if (TestTrinomials())
                return;
            if (TestPentanomials())
                return;
            
            TestRandom();
        }

        /// <summary>
        /// Computes the field polynomial. This can take a long time for big degrees.
        /// </summary>
        protected void ComputeFieldPolynomial2()
        {
            if (TestTrinomials())
                return;
            if (TestPentanomials())
                return;
            
            TestRandom();
        }

        /// <summary>
        /// Compute a random root of the given GF2Polynomial
        /// </summary>
        /// 
        /// <param name="G">The polynomial</param>
        /// 
        /// <returns>Returns a random root of <c>G</c></returns>
        public override GF2nElement RandomRoot(GF2Polynomial G)
        {
            // We are in B1!!!
            GF2nPolynomial c;
            GF2nPolynomial ut;
            GF2nElement u;
            GF2nPolynomial h;
            int hDegree;
            // 1. Set g(t) <- f(t)
            GF2nPolynomial g = new GF2nPolynomial(G, this);
            int gDegree = g.Degree;
            int i;

            // 2. while deg(g) > 1
            while (gDegree > 1)
            {
                do
                {
                    // 2.1 choose random u (element of) GF(2^m)
                    u = new GF2nPolynomialElement(this, new Random());
                    ut = new GF2nPolynomial(2, GF2nPolynomialElement.Zero(this));
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
                else
                    g = new GF2nPolynomial(h); // ... else g(t) <- h(t)

                gDegree = g.Degree;
            }

            // 3. Output g(0)
            return g.At(0);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Computes a new squaring matrix used for fast squaring
        /// </summary>
        private void ComputeSquaringMatrix()
        {
            GF2Polynomial[] d = new GF2Polynomial[DegreeN - 1];
            int i, j;
            m_squaringMatrix = new GF2Polynomial[DegreeN];

            for (i = 0; i < m_squaringMatrix.Length; i++)
                m_squaringMatrix[i] = new GF2Polynomial(DegreeN, "ZERO");

            for (i = 0; i < DegreeN - 1; i++)
                d[i] = new GF2Polynomial(1, "ONE").ShiftLeft(DegreeN + i).Remainder(FieldPoly);
            
            for (i = 1; i <= Math.Abs(DegreeN >> 1); i++)
            {
                for (j = 1; j <= DegreeN; j++)
                {
                    if (d[DegreeN - (i << 1)].TestBit(DegreeN - j))
                        m_squaringMatrix[j - 1].SetBit(DegreeN - i);
                }
            }

            for (i = Math.Abs(DegreeN >> 1) + 1; i <= DegreeN; i++)
                m_squaringMatrix[(i << 1) - DegreeN - 1].SetBit(DegreeN - i);
        }

        /// <summary>
        /// Tests all pentanomials of degree (n+1) until a irreducible is found and stores the result in <c>field polynomial</c>.
        /// Returns false if no irreducible pentanomial exists in GF(2^n).
        /// This can take very long for huge degrees.
        /// </summary>
        /// 
        /// <returns>Returns true if an irreducible pentanomial is found</returns>
        private bool TestPentanomials()
        {
            int i, j, k, l;
            bool done = false;
            l = 0;

            FieldPoly = new GF2Polynomial(DegreeN + 1);
            FieldPoly.SetBit(0);
            FieldPoly.SetBit(DegreeN);

            for (i = 1; (i <= (DegreeN - 3)) && !done; i++)
            {
                FieldPoly.SetBit(i);
                for (j = i + 1; (j <= (DegreeN - 2)) && !done; j++)
                {
                    FieldPoly.SetBit(j);
                    for (k = j + 1; (k <= (DegreeN - 1)) && !done; k++)
                    {
                        FieldPoly.SetBit(k);
                        if (((DegreeN & 1) != 0) | ((i & 1) != 0) | ((j & 1) != 0)
                            | ((k & 1) != 0))
                        {
                            done = FieldPoly.IsIrreducible();
                            l++;
                            if (done)
                            {
                                m_isPentanomial = true;
                                m_pc[0] = i;
                                m_pc[1] = j;
                                m_pc[2] = k;
                                return done;
                            }
                        }
                        FieldPoly.ResetBit(k);
                    }
                    FieldPoly.ResetBit(j);
                }
                FieldPoly.ResetBit(i);
            }

            return done;
        }

        /// <summary>
        /// Tests random polynomials of degree (n+1) until an irreducible is found and stores the result in <c>field polynomial</c>.
        /// This can take very long for huge degrees.
        /// </summary>
        /// 
        /// <returns>Returns true</returns>
        private bool TestRandom()
        {
            int l;
            bool done = false;

            FieldPoly = new GF2Polynomial(DegreeN + 1);
            l = 0;

            while (!done)
            {
                l++;
                FieldPoly.Randomize();
                FieldPoly.SetBit(DegreeN);
                FieldPoly.SetBit(0);
                if (FieldPoly.IsIrreducible())
                {
                    done = true;
                    return done;
                }
            }

            return done;
        }

        /// <summary>
        /// Tests all trinomials of degree (n+1) until a irreducible is found and stores the result in <c>field polynomial</c>.
        /// Returns false if no irreducible trinomial exists in GF(2^n). This can take very long for huge degrees.
        /// </summary>
        /// 
        /// <returns>Returns true if an irreducible trinomial is found</returns>
        private bool TestTrinomials()
        {
            int i, l;
            bool done = false;
            l = 0;

            FieldPoly = new GF2Polynomial(DegreeN + 1);
            FieldPoly.SetBit(0);
            FieldPoly.SetBit(DegreeN);
            for (i = 1; (i < DegreeN) && !done; i++)
            {
                FieldPoly.SetBit(i);
                done = FieldPoly.IsIrreducible();
                l++;
                if (done)
                {
                    m_isTrinomial = true;
                    m_tc = i;
                    return done;
                }
                FieldPoly.ResetBit(i);
                done = FieldPoly.IsIrreducible();
            }

            return done;
        }
        #endregion
    }
}
