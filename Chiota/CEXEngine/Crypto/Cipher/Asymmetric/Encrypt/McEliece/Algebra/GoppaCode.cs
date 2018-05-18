#region Directives
using System;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class describes decoding operations of an irreducible binary Goppa code.
    /// <para>A check matrix H of the Goppa code and an irreducible Goppa polynomial are used 
    /// the operations are worked over a finite field GF(2^m)</para>
    /// </summary>
    internal sealed class GoppaCode
    {
        /// <summary>
        /// Default constructor 
        /// </summary>
        private GoppaCode()
        {
        }

        /// <summary>
        /// This class is a container for two instances of GF2Matrix and one instance of Permutation. 
        /// <para>It is used to hold the systematic form <c>S*H*P = (Id|M)</c> of the check matrix <c>H</c> as
        /// returned by GoppaCode.ComputeSystematicForm(GF2Matrix, IRandom).</para>
        /// </summary>
        public class MaMaPe
        {
            #region Fields
            private GF2Matrix m_S, m_H;
            private Permutation m_P;
            #endregion

            #region Constructor
            /// <summary>
            /// Construct a new MaMaPe container with the given parameters
            /// </summary>
            /// 
            /// <param name="S">The first matrix</param>
            /// <param name="H">The second matrix</param>
            /// <param name="P">The permutation</param>
            public MaMaPe(GF2Matrix S, GF2Matrix H, Permutation P)
            {
                m_S = S;
                m_H = H;
                m_P = P;
            }
            #endregion

            #region Properties
            /// <summary>
            /// Get: Return the first matrix
            /// </summary>
            public GF2Matrix FirstMatrix
            {
                get { return m_S; }
            }

            /// <summary>
            /// Get: Return the second matrix
            /// </summary>
            public GF2Matrix SecondMatrix
            {
                get { return m_H; }
            }

            /// <summary>
            /// Get: Return the permutation
            /// </summary>
            public Permutation Permutation
            {
                get { return m_P; }
            }
            #endregion
        }

        /// <summary>
        /// This class is a container for an instance of GF2Matrix and one int[].
        /// <para>It is used to hold a generator matrix and the set of indices such that 
        /// the submatrix of the generator matrix consisting of the specified columns is the identity.</para>
        /// </summary>
        public class MatrixSet
        {
            #region Fields
            private GF2Matrix m_G;
            private int[] _setJ;
            #endregion

            #region Constructor
            /// <summary>
            /// onstruct a new MatrixSet container with the given parameters
            /// </summary>
            /// 
            /// <param name="G">The generator matrix</param>
            /// <param name="SetJ">The set of indices such that the submatrix of the generator matrix 
            /// consisting of the specified columns is the identity</param>
            public MatrixSet(GF2Matrix G, int[] SetJ)
            {
                m_G = G;
                _setJ = SetJ;
            }
            #endregion

            #region Properties
            /// <summary>
            /// Get: Return the generator matrix
            /// </summary>
            public GF2Matrix G
            {
                get { return m_G; }
            }

            /// <summary>
            /// Get: Returns the set of indices such that the submatrix of the generator 
            /// matrix consisting of the specified columns is the identity
            /// </summary>
            public int[] SetJ
            {
                get { return _setJ; }
            }
            #endregion
        }

        #region Public Methods
        /// <summary>
        /// Construct the check matrix of a Goppa code in canonical form from the irreducible Goppa polynomial over the finite field <c>GF(2^m)</c>.
        /// </summary>
        /// 
        /// <param name="Field">The finite field</param>
        /// <param name="Gp">The irreducible Goppa polynomial</param>
        /// 
        /// <returns>The new GF2Matrix</returns>
        public static GF2Matrix CreateCanonicalCheckMatrix(GF2mField Field, PolynomialGF2mSmallM Gp)
        {
            int m = Field.Degree;
            int n = 1 << m;
            int t = Gp.Degree;
            // create matrix H over GF(2^m)
            int[][] hArray = ArrayUtils.CreateJagged<int[][]>(t, n);
            // create matrix YZ
            int[][] yz = ArrayUtils.CreateJagged<int[][]>(t, n);

            if (ParallelUtils.IsParallel)
            {
                Parallel.For(0, n, j =>
                    yz[0][j] = Field.Inverse(Gp.EvaluateAt(j)));
            }
            else
            {
                // here j is used as index and as element of field GF(2^m)
                for (int j = 0; j < n; j++)
                    yz[0][j] = Field.Inverse(Gp.EvaluateAt(j));
            }

            for (int i = 1; i < t; i++)
            {
                // here j is used as index and as element of field GF(2^m)
                if (ParallelUtils.IsParallel)
                {
                    Parallel.For(0, n, j =>
                    {
                        yz[i][j] = Field.Multiply(yz[i - 1][j], j);
                    });
                }
                else
                {
                    for (int j = 0; j < n; j++)
                        yz[i][j] = Field.Multiply(yz[i - 1][j], j);
                }
            }

            // create matrix H = XYZ 
            for (int i = 0; i < t; i++)
            {
                if (ParallelUtils.IsParallel)
                {
                    Parallel.For(0, n, j =>
                    {
                        for (int k = 0; k <= i; k++)
                            hArray[i][j] = Field.Add(hArray[i][j], Field.Multiply(yz[k][j], Gp.GetCoefficient(t + k - i)));
                    });
                }
                else
                {
                    for (int j = 0; j < n; j++)
                    {
                        for (int k = 0; k <= i; k++)
                            hArray[i][j] = Field.Add(hArray[i][j], Field.Multiply(yz[k][j], Gp.GetCoefficient(t + k - i)));
                    }
                }
            }

            // convert to matrix over GF(2)
            int[][] result = ArrayUtils.CreateJagged<int[][]>(t * m, IntUtils.URShift((n + 31), 5));

            if (ParallelUtils.IsParallel)
            {
                for (int j = 0; j < n; j++)
                {
                    int q = IntUtils.URShift(j, 5);
                    int r = 1 << (j & 0x1f);
                    for (int i = 0; i < t; i++)
                    {
                        int e = hArray[i][j];
                        Parallel.For(0, m, u =>
                        {
                            int b = (IntUtils.URShift(e, u)) & 1;
                            if (b != 0)
                            {
                                int ind = (i + 1) * m - u - 1;
                                result[ind][q] ^= r;
                            }
                        });
                    }
                }
            }
            else
            {
                for (int j = 0; j < n; j++)
                {
                    int q = IntUtils.URShift(j, 5);
                    int r = 1 << (j & 0x1f);
                    for (int i = 0; i < t; i++)
                    {
                        int e = hArray[i][j];
                        for (int u = 0; u < m; u++)
                        {
                            int b = (IntUtils.URShift(e, u)) & 1;
                            if (b != 0)
                            {
                                int ind = (i + 1) * m - u - 1;
                                result[ind][q] ^= r;
                            }
                        }
                    }
                }
            }

            return new GF2Matrix(n, result);
        }

        /// <summary>
        /// Given a check matrix <c>H</c>, compute matrices <c>S</c>, <c>M</c>, and a random permutation <c>P</c> such that 
        /// <c>S*H*P = (Id|M)</c>. Return <c>S^-1</c>, <c>M</c>, and the systematic form of H
        /// </summary>
        /// 
        /// <param name="H">The check matrix</param>
        /// <param name="SecRnd">The source of randomness</param>
        /// 
        /// <returns>Returns the tuple <c>(S^-1, M, P)</c></returns>
        public static MaMaPe ComputeSystematicForm(GF2Matrix H, IRandom SecRnd)
        {
            MaMaPe mmp = null;
            object lockobj = new object();

            if (ParallelUtils.IsParallel)
            {
                Func<bool> condFn = () => mmp == null;
                ParallelUtils.Loop(new ParallelOptions(), condFn, loopState =>
                {
                    MaMaPe mmp2 = GetMMP(H, SecRnd);
                    
                    if (mmp2 != null)
                    {
                        lock (mmp2)
                        {
                            mmp = mmp2;
                        }
                    }
                });
            }
            else
            {
                do
                {
                    mmp = GetMMP(H, SecRnd);
                }
                while (mmp == null);
            }

            return mmp;
        }

        private static MaMaPe GetMMP(GF2Matrix H, IRandom SecRnd)
        {
            int n = H.ColumnCount;
            GF2Matrix s = null;
            Permutation p = new Permutation(n, SecRnd);
            GF2Matrix hp = (GF2Matrix)H.RightMultiply(p);
            GF2Matrix sInv = hp.LeftSubMatrix();

            if ((s = InvertMatrix(sInv)) == null)
                return null;

            GF2Matrix shp = (GF2Matrix)s.RightMultiply(hp);
            GF2Matrix m = shp.RightSubMatrix();

            return new MaMaPe(sInv, m, p);
        }

        private static GF2Matrix InvertMatrix(GF2Matrix Matrix)
        {
            try
            {
                return (GF2Matrix)Matrix.ComputeInverse();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Find an error vector <c>E</c> over <c>GF(2)</c> from an input syndrome <c>S</c> over <c>GF(2^M)</c>
        /// </summary>
        /// 
        /// <param name="SyndVec">The syndrome</param>
        /// <param name="Field">The finite field</param>
        /// <param name="Gp">The irreducible Goppa polynomial</param>
        /// <param name="SqRootMatrix">The matrix for computing square roots in <c>(GF(2M))<sup>T</sup></c></param>
        /// 
        /// <returns>The error vector</returns>
        public static GF2Vector SyndromeDecode(GF2Vector SyndVec, GF2mField Field, PolynomialGF2mSmallM Gp, PolynomialGF2mSmallM[] SqRootMatrix)
        {
            int n = 1 << Field.Degree;
            // the error vector
            GF2Vector errors = new GF2Vector(n);

            // if the syndrome vector is zero, the error vector is also zero
            if (!SyndVec.IsZero())
            {
                // convert syndrome vector to polynomial over GF(2^m)
                PolynomialGF2mSmallM syndrome = new PolynomialGF2mSmallM(SyndVec.ToExtensionFieldVector(Field));
                // compute T = syndrome^-1 mod gp
                PolynomialGF2mSmallM t = syndrome.ModInverse(Gp);
                // compute tau = sqRoot(T + X) mod gp
                PolynomialGF2mSmallM tau = t.AddMonomial(1);
                tau = tau.ModSquareRootMatrix(SqRootMatrix);
                // compute polynomials a and b satisfying a + b*tau = 0 mod gp
                PolynomialGF2mSmallM[] ab = tau.ModPolynomialToFracton(Gp);
                // compute the polynomial a^2 + X*b^2
                PolynomialGF2mSmallM a2 = ab[0].Multiply(ab[0]);
                PolynomialGF2mSmallM b2 = ab[1].Multiply(ab[1]);
                PolynomialGF2mSmallM xb2 = b2.MultWithMonomial(1);
                PolynomialGF2mSmallM a2plusXb2 = a2.Add(xb2);
                // normalize a^2 + X*b^2 to obtain the error locator polynomial
                int headCoeff = a2plusXb2.Head;
                int invHeadCoeff = Field.Inverse(headCoeff);
                PolynomialGF2mSmallM elp = a2plusXb2.MultWithElement(invHeadCoeff);

                // for all elements i of GF(2^m)
                for (int i = 0; i < n; i++)
                {
                    // evaluate the error locator polynomial at i
                    int z = elp.EvaluateAt(i);
                    // if polynomial evaluates to zero
                    if (z == 0)
                    {
                        // set the i-th coefficient of the error vector
                        errors.SetBit(i);
                    }
                }
            }

            return errors;
        }
        #endregion
    }
}
