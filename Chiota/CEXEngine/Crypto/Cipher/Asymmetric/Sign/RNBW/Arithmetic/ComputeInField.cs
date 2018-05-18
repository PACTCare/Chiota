#region Directives
using System;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.Arithmetic
{
    /// <summary>
    /// This class offers different operations on matrices in field GF2^8.
    /// <para>Implements functions for finding inverse of a matrix, 
    /// solving linear equation systems using the Gauss-Elimination method,
    /// and basic operations like matrix multiplication, addition and so on.</para>
    /// </summary>
    internal sealed class ComputeInField : IDisposable
    {
        #region Fields
        private short[][] m_A;
        private short[] m_X;
        private bool m_isDisposed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public ComputeInField()
        {
        }
        
        /// <summary>
        /// Finalize objects
        /// </summary>
        ~ComputeInField()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds the n x n matrices matrix1 and matrix2
        /// </summary>
        /// <param name="M1">The first summand</param>
        /// <param name="M2">The second summand</param>
        /// <returns>Returns addition of matrix1 and matrix2; both having the dimensions n x n</returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if the addition is not possible because of different dimensions of the matrices</exception>
        public short[][] AddSquareMatrix(short[][] M1, short[][] M2)
        {
            if (M1.Length != M2.Length || M1[0].Length != M2[0].Length)
                throw new CryptoAsymmetricSignException("ComputeInField:AddSquareMatrix", "Addition is not possible!", new ArgumentException());

            short[][] rslt = ArrayUtils.CreateJagged<short[][]>(M1.Length, M1.Length);

            for (int i = 0; i < M1.Length; i++)
            {
                for (int j = 0; j < M2.Length; j++)
                    rslt[i][j] = GF2Field.AddElem(M1[i][j], M2[i][j]);
            }

            return rslt;
        }

        /// <summary>
        /// Addition of two vectors.
        /// </summary>
        /// 
        /// <param name="V1">The first summand, always of dim n</param>
        /// <param name="V2">The second summand, always of dim n</param>
        /// 
        /// <returns>Returns <c>V1+V2</c></returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if the addition is impossible due to inconsistency in the dimensions</exception>
        public short[] AddVect(short[] V1, short[] V2)
        {
            if (V1.Length != V2.Length)
                throw new CryptoAsymmetricSignException("ComputeInField:AddVect", "Addition is not possible!", new ArgumentException());
            
            short[] rslt = new short[V1.Length];

            for (int n = 0; n < rslt.Length; n++)
                rslt[n] = GF2Field.AddElem(V1[n], V2[n]);
            
            return rslt;
        }

        /// <summary>
        /// This function computes the inverse of a given matrix using the Gauss-Elimination method.
        /// <para>An exception is thrown if the matrix has no inverse</para>
        /// </summary>
        /// 
        /// <param name="Coef">The matrix which inverse matrix is needed</param>
        /// 
        /// <returns>The inverse matrix of the input matrix</returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if the given matrix is not invertible</exception>
        public short[][] Inverse(short[][] Coef)
        {
            try
            {
                short factor;
                short[][] inverse;

                m_A = ArrayUtils.CreateJagged<short[][]>(Coef.Length, 2 * Coef.Length);

                if (Coef.Length != Coef[0].Length)
                    throw new CryptoAsymmetricSignException("ComputeInField:Inverse", "The matrix is not invertible!", new ArgumentException());

                // prepare: Copy coef and the identity matrix into the global A
                for (int i = 0; i < Coef.Length; i++)
                {
                    // copy the input matrix coef into A
                    for (int j = 0; j < Coef.Length; j++)
                        m_A[i][j] = Coef[i][j];

                    // copy the identity matrix into A.
                    for (int j = Coef.Length; j < 2 * Coef.Length; j++)
                        m_A[i][j] = 0;
                    
                    m_A[i][i + m_A.Length] = 1;
                }

                // Elimination operations to get the identity matrix from the left side of A, modify A to get 0s under the diagonal
                ComputeZerosUnder(true);

                // modify A to get only 1s on the diagonal: A[i][j] =A[i][j]/A[i][i]
                for (int i = 0; i < m_A.Length; i++)
                {
                    factor = GF2Field.InvElem(m_A[i][i]);
                    for (int j = i; j < 2 * m_A.Length; j++)
                        m_A[i][j] = GF2Field.MultElem(m_A[i][j], factor);
                }

                //modify A to get only 0s above the diagonal.
                ComputeZerosAbove();

                // copy the result (the second half of A) in the matrix inverse
                inverse = ArrayUtils.CreateJagged<short[][]>(m_A.Length, m_A.Length);

                for (int i = 0; i < m_A.Length; i++)
                {
                    for (int j = m_A.Length; j < 2 * m_A.Length; j++)
                        inverse[i][j - m_A.Length] = m_A[i][j];
                }

                return inverse;

            }
            catch
            {
                // The matrix is not invertible! A new one should be generated!
                return null;
            }
        }

        /// <summary>
        /// This function multiplies two given matrices.
        /// <para>If the given matrices cannot be multiplied due to different sizes, an exception is thrown.</para>
        /// </summary>
        /// 
        /// <param name="M1">The 1st matrix</param>
        /// <param name="M2">The 2nd matrix</param>
        /// 
        /// <returns></returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if the given matrices cannot be multiplied due to different dimensions</exception>
        public short[][] MultiplyMatrix(short[][] M1, short[][] M2)
        {

            if (M1[0].Length != M2.Length)
                throw new CryptoAsymmetricSignException("ComputeInField:MultiplyMatrix", "Multiplication is not possible!", new ArgumentException());
            
            short tmp = 0;
            m_A = ArrayUtils.CreateJagged<short[][]>(M1.Length, M2[0].Length);

            for (int i = 0; i < M1.Length; i++)
            {
                for (int j = 0; j < M2.Length; j++)
                {
                    for (int k = 0; k < M2[0].Length; k++)
                    {
                        tmp = GF2Field.MultElem(M1[i][j], M2[j][k]);
                        m_A[i][k] = GF2Field.AddElem(m_A[i][k], tmp);
                    }
                }
            }
            return m_A;
        }

        /// <summary>
        /// This function multiplies a given matrix with a one-dimensional array.
        /// <para>An exception is thrown, if the number of columns in the matrix and the number of rows in the one-dimensional array differ.</para>
        /// </summary>
        /// 
        /// <param name="M1">The matrix to be multiplied</param>
        /// <param name="M">The one-dimensional array to be multiplied</param>
        /// 
        /// <returns>Returns <c>M1*m</c></returns>
        /// 
        /// <exception cref="ArgumentException">Thrown in case of dimension inconsistency</exception>
        public short[] MultiplyMatrix(short[][] M1, short[] M)
        {
            if (M1[0].Length != M.Length)
                throw new CryptoAsymmetricSignException("ComputeInField:MultiplyMatrix", "Multiplication is not possible!", new ArgumentException());
            
            short tmp = 0;
            short[] B = new short[M1.Length];

            for (int i = 0; i < M1.Length; i++)
            {
                for (int j = 0; j < M.Length; j++)
                {
                    tmp = GF2Field.MultElem(M1[i][j], M[j]);
                    B[i] = GF2Field.AddElem(B[i], tmp);
                }
            }

            return B;
        }

        /// <summary>
        /// Multiplies matrix with scalar
        /// </summary>
        /// 
        /// <param name="Scalar">The scalar galois element to multiply matrix with</param>
        /// <param name="Matrix">The matrix 2-dim n x n matrix to be multiplied</param>
        /// 
        /// <returns>Returns matrix multiplied with scalar</returns>
        public short[][] MultMatrix(short Scalar, short[][] Matrix)
        {
            short[][] res = ArrayUtils.CreateJagged<short[][]>(Matrix.Length, Matrix[0].Length);

            for (int i = 0; i < Matrix.Length; i++)
            {
                for (int j = 0; j < Matrix[0].Length; j++)
                    res[i][j] = GF2Field.MultElem(Scalar, Matrix[i][j]);
            }

            return res;
        }

        /// <summary>
        /// Multiplies vector with scalar
        /// </summary>
        /// 
        /// <param name="Scalar">The scalar galois element to multiply vector with</param>
        /// <param name="Vector">The vector to be multiplied</param>
        /// 
        /// <returns>Returns vector multiplied with scalar</returns>
        public short[] MultVect(short Scalar, short[] Vector)
        {
            short[] res = new short[Vector.Length];

            for (int n = 0; n < res.Length; n++)
                res[n] = GF2Field.MultElem(Scalar, Vector[n]);
            
            return res;
        }

        /// <summary>
        /// Multiplication of column vector with row vector
        /// </summary>
        /// 
        /// <param name="V1"> column vector, always n x 1</param>
        /// <param name="V2"> row vector, always 1 x n</param>
        /// 
        /// <returns> resulting n x n matrix of multiplication</returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if the multiplication is impossible due to inconsistency in the dimensions</exception>
        public short[][] MultVects(short[] V1, short[] V2)
        {
            if (V1.Length != V2.Length)
                throw new CryptoAsymmetricSignException("ComputeInField:MultVects", "Multiplication is not possible!", new ArgumentException());

            short[][] rslt = ArrayUtils.CreateJagged<short[][]>(V1.Length, V2.Length);

            for (int i = 0; i < V1.Length; i++)
            {
                for (int j = 0; j < V2.Length; j++)
                    rslt[i][j] = GF2Field.MultElem(V1[i], V2[j]);
            }

            return rslt;
        }

        /// <summary>
        /// This function finds a solution of the equation Bx = b.
        /// </summary>
        /// 
        /// <param name="B">This matrix is the left part of the equation (B in the equation above)</param>
        /// <param name="Br">The right part of the equation (b in the equation above)</param>
        /// 
        /// <returns>The solution of the equation if it is solvable null otherwise</returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if LES is not solvable</exception>
        public short[] SolveEquation(short[][] B, short[] Br)
        {
            try
            {
                if (B.Length != Br.Length)
                    throw new CryptoAsymmetricSignException("ComputeInField:SolveEquation", "The equation system is not solvable!", new ArgumentException());

                // initialize this matrix stores B and b from the equation B*x = b, b is stored as the last column.
                // B contains one column more than rows, In this column we store a free coefficient that should be later subtracted from b
                m_A = ArrayUtils.CreateJagged<short[][]>(B.Length, B.Length + 1);
                // stores the solution of the LES
                m_X = new short[B.Length];

                // copy B into the global matrix A
                for (int i = 0; i < B.Length; i++)
                {
                    for (int j = 0; j < B[0].Length; j++)
                        m_A[i][j] = B[i][j];
                }

                // copy the vector b into the global A
                // the free coefficient, stored in the last column of A( A[i][b.Length] is to be subtracted from b
                for (int i = 0; i < Br.Length; i++)
                    m_A[i][Br.Length] = GF2Field.AddElem(Br[i], m_A[i][Br.Length]);

                // call the methods for gauss elimination and backward substitution
                ComputeZerosUnder(false);     // obtain zeros under the diagonal
                Substitute();

                return m_X;

            }
            catch
            {
                // the LES is not solvable!
                return null; 
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Elimination under the diagonal.
        /// <para>This function changes a matrix so that it contains only zeros under the diagonal(Ai,i) using only Gauss-Elimination operations.
        /// It is used in solveEquaton as well as in the function for finding an inverse of a matrix: inverse.
        /// Both of them use the Gauss-Elimination Method.
        /// The result is stored in the global matrix A</para>
        /// </summary>
        /// 
        /// <param name="ForInverse">Shows if the function is used by the solveEquation-function or by the inverse-function and according to this creates matrices of different sizes.</param>
        /// 
        /// <exception cref="ArgumentException">Thrown if the multiplicative inverse of 0 is needed</exception>
        private void ComputeZerosUnder(bool ForInverse)
        {

            // the number of columns in the global A where the tmp results are stored
            int length;
            short tmp = 0;

            // the function is used in inverse() - A should have 2 times more columns than rows
            if (ForInverse)
                length = 2 * m_A.Length;
            // the function is used in solveEquation - A has 1 column more than rows
            else
                length = m_A.Length + 1;

            // elimination operations to modify A so that that it contains only 0s under the diagonal
            for (int k = 0; k < m_A.Length - 1; k++) // the fixed row
            {
                for (int i = k + 1; i < m_A.Length; i++)
                {
                    short factor1 = m_A[i][k];
                    short factor2 = GF2Field.InvElem(m_A[k][k]);

                    // The element which multiplicative inverse is needed, is 0 in this case is the input matrix not invertible
                    if (factor2 == 0)
                        throw new CryptoAsymmetricSignException("ComputeInField:ComputeZerosUnder", "Matrix not invertible!", new ArgumentException());

                    for (int j = k; j < length; j++)
                    {// columns
                        // tmp=A[k,j] / A[k,k]
                        tmp = GF2Field.MultElem(m_A[k][j], factor2);
                        // tmp = A[i,k] * A[k,j] / A[k,k]
                        tmp = GF2Field.MultElem(factor1, tmp);
                        // A[i,j]=A[i,j]-A[i,k]/A[k,k]*A[k,j];
                        m_A[i][j] = GF2Field.AddElem(m_A[i][j], tmp);
                    }
                }
            }
        }

        /// <summary>
        /// Elimination above the diagonal.
        /// <para>This function changes a matrix so that it contains only zeros above the diagonal(Ai,i) using only Gauss-Elimination operations.
        /// It is used in the inverse-function
        /// The result is stored in the global matrix A.</para>
        /// </summary>
        /// 
        /// <exception cref="ArgumentException">Thrown if a multiplicative inverse of 0 is needed</exception>
        private void ComputeZerosAbove()
        {
            short tmp = 0;
            for (int k = m_A.Length - 1; k > 0; k--) // the fixed row
            {
                for (int i = k - 1; i >= 0; i--) // rows
                {
                    short factor1 = m_A[i][k];
                    short factor2 = GF2Field.InvElem(m_A[k][k]);

                    if (factor2 == 0)
                        throw new CryptoAsymmetricSignException("ComputeInField:ComputeZerosAbove", "Matrix not invertible!", new ArgumentException());
                    
                    for (int j = k; j < 2 * m_A.Length; j++) // columns
                    {
                        tmp = GF2Field.MultElem(m_A[k][j], factor2);
                        tmp = GF2Field.MultElem(factor1, tmp);
                        m_A[i][j] = GF2Field.AddElem(m_A[i][j], tmp);
                    }
                }
            }
        }

        /// <summary>
        /// This function uses backward substitution to find x of the linear equation system (LES) B*x = b, 
        /// where A a triangle-matrix is (contains only zeros under the diagonal) and b is a vector.
        /// <para>If the multiplicative inverse of 0 is needed, an exception is thrown. 
        /// In this case is the LES not solvable.</para>
        /// </summary>
        /// 
        /// <exception cref="ArgumentException">Thrown if a multiplicative inverse of 0 is needed</exception>
        private void Substitute()
        {

            // for the temporary results of the operations in field
            short tmp, temp;

            temp = GF2Field.InvElem(m_A[m_A.Length - 1][m_A.Length - 1]);

            if (temp == 0)
                throw new CryptoAsymmetricSignException("ComputeInField:Substitute", "The equation system is not solvable!", new ArgumentException());

            // backward substitution
            m_X[m_A.Length - 1] = GF2Field.MultElem(m_A[m_A.Length - 1][m_A.Length], temp);
            for (int i = m_A.Length - 2; i >= 0; i--)
            {
                tmp = m_A[i][m_A.Length];
                for (int j = m_A.Length - 1; j > i; j--)
                {
                    temp = GF2Field.MultElem(m_A[i][j], m_X[j]);
                    tmp = GF2Field.AddElem(tmp, temp);
                }

                temp = GF2Field.InvElem(m_A[i][i]);

                if (temp == 0)
                    throw new CryptoAsymmetricSignException("ComputeInField:Substitute", "Not a solvable equation system!", new ArgumentException());
                
                m_X[i] = GF2Field.MultElem(tmp, temp);
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (m_A != null)
                    {
                        Array.Clear(m_A, 0, m_A.Length);
                        m_A = null;
                    }
                    if (m_X != null)
                    {
                        Array.Clear(m_X, 0, m_X.Length);
                        m_X = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
