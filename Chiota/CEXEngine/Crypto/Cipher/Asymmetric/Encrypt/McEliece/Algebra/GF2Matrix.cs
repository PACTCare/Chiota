#region Directives
using System;
using System.Text;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class describes some operations with matrices over finite field GF(2) and is used in ecc and MQ-PKC (also has some specific methods and implementation).
    /// </summary>
    internal sealed class GF2Matrix : Matrix
    {
        #region Fields
        // For the matrix representation the array of type int[][] is used, thus one
        // element of the array keeps 32 elements of the matrix (from one row and 32 columns)
        private int[][] m_matrix;
        //the length of each array representing a row of this matrix, computed as (numColumns + 31) / 32
        private int m_length;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the length of each array representing a row of this matrix
        /// </summary>
        public int Length
        {
            get { return m_length; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Create the matrix from encoded form
        /// </summary>
        /// 
        /// <param name="Encoded">The encoded matrix</param>
        public GF2Matrix(byte[] Encoded)
        {
            if (Encoded.Length < 9)
                throw new ArithmeticException("Encoded array is not an encoded matrix over GF(2)!");

            RowCount = LittleEndian.OctetsToInt(Encoded, 0);
            ColumnCount = LittleEndian.OctetsToInt(Encoded, 4);
            int n = (IntUtils.URShift((ColumnCount + 7), 3)) * RowCount;

            if ((RowCount <= 0) || (n != (Encoded.Length - 8)))
                throw new ArithmeticException("Encoded array is not an encoded matrix over GF(2)!");
            
            m_length = IntUtils.URShift((ColumnCount + 31), 5);
            m_matrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);

            // number of "full" integer
            int q = ColumnCount >> 5;
            // number of bits in non-full integer
            int r = ColumnCount & 0x1f;

            int count = 8;
            for (int i = 0; i < RowCount; i++)
            {
                for (int j = 0; j < q; j++, count += 4)
                    m_matrix[i][j] = LittleEndian.OctetsToInt(Encoded, count);
                
                for (int j = 0; j < r; j += 8)
                    m_matrix[i][q] ^= (Encoded[count++] & 0xff) << j;
            }
        }

        /// <summary>
        /// Create the matrix with the contents of the given array.
        /// <para>The matrix is not copied. Unused coefficients are masked out.</para>
        /// </summary>
        /// 
        /// <param name="Columns">The number of columns</param>
        /// <param name="Matrix">The element array</param>
        public GF2Matrix(int Columns, int[][] Matrix) //f1
        {
            if (Matrix[0].Length != (Columns + 31) >> 5)
                throw new ArithmeticException("Int array does not match given number of columns!");
            
            this.ColumnCount = Columns;
            RowCount = Matrix.Length;
            m_length = Matrix[0].Length;
            int rest = Columns & 0x1f;
            int bitMask;

            if (rest == 0)
                bitMask = unchecked((int)0xffffffff);
            else
                bitMask = (1 << rest) - 1;
            
            for (int i = 0; i < RowCount; i++)
                Matrix[i][m_length - 1] &= bitMask;
            
            m_matrix = Matrix;
        }

        /// <summary>
        /// Create an nxn matrix of the given type
        /// </summary>
        /// 
        /// <param name="N">The matrix size</param>
        /// <param name="MatrixType">The matrix type</param>
        /// <param name="SecRnd">The source of randomness</param>
        public GF2Matrix(int N, char MatrixType, IRandom SecRnd)
        {
            if (N <= 0)
                throw new ArithmeticException("GF2Matrix: Size of matrix is non-positive!");

            switch (MatrixType)
            {

                case Matrix.MATRIX_TYPE_ZERO:
                    AssignZeroMatrix(N, N);
                    break;
                case Matrix.MATRIX_TYPE_UNIT:
                    AssignUnitMatrix(N);
                    break;
                case Matrix.MATRIX_TYPE_RANDOM_LT:
                    AssignRandomLowerTriangularMatrix(N, SecRnd);
                    break;
                case Matrix.MATRIX_TYPE_RANDOM_UT:
                    AssignRandomUpperTriangularMatrix(N, SecRnd);
                    break;
                case Matrix.MATRIX_TYPE_RANDOM_REGULAR:
                    AssignRandomRegularMatrix(N, SecRnd);
                    break;
                default:
                    throw new ArithmeticException("GF2Matrix: Unknown matrix type!");
            }
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// 
        /// <param name="A">A GF2Matrix to copy</param>
        public GF2Matrix(GF2Matrix A)
        {
            ColumnCount = A.ColumnCount;
            RowCount = A.RowCount;
            m_length = A.m_length;
            m_matrix = new int[A.m_matrix.Length][];

            for (int i = 0; i < m_matrix.Length; i++)
                m_matrix[i] = IntUtils.DeepCopy(A.m_matrix[i]);
        }

        /// <summary>
        /// Create the mxn zero matrix
        /// </summary>
        private GF2Matrix(int M, int N)
        {
            if ((N <= 0) || (M <= 0))
                throw new ArithmeticException("GF2Matrix: Size of matrix is non-positive!");

            AssignZeroMatrix(M, N);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Partially add one row to another
        /// </summary>
        /// 
        /// <param name="FromRow">The addend</param>
        /// <param name="ToRow">The row to add to</param>
        /// <param name="StartIndex">The array index to start from</param>
        private static void AddToRow(int[] FromRow, int[] ToRow, int StartIndex)
        {
            for (int i = ToRow.Length - 1; i >= StartIndex; i--)
                ToRow[i] = FromRow[i] ^ ToRow[i];
        }

        /// <summary>
        /// Create the mxn zero matrix
        /// </summary>
        /// <param name="M">Number of rows</param>
        /// <param name="N">Number of columns</param>
        private void AssignZeroMatrix(int M, int N)
        {
            RowCount = M;
            ColumnCount = N;
            m_length = IntUtils.URShift((N + 31), 5);
            m_matrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);

            for (int i = 0; i < RowCount; i++)
            {
                Array.Clear(m_matrix[i], 0, m_length);
                //for (int j = 0; j < m_length; j++)
                //    m_matrix[i][j] = 0;
            }
        }

        /// <summary>
        /// Create the mxn unit matrix
        /// </summary>
        /// 
        /// <param name="N">Number of rows (and columns)</param>
        private void AssignUnitMatrix(int N)
        {
            RowCount = N;
            ColumnCount = N;
            m_length = IntUtils.URShift((N + 31), 5);
            m_matrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);

            for (int i = 0; i < RowCount; i++)
            {
                for (int j = 0; j < m_length; j++)
                    m_matrix[i][j] = 0;
            }
            for (int i = 0; i < RowCount; i++)
            {
                int rest = i & 0x1f;
                m_matrix[i][IntUtils.URShift(i, 5)] = 1 << rest;
            }
        }

        /// <summary>
        /// Create a nxn random lower triangular matrix
        /// </summary>
        /// 
        /// <param name="N">Number of rows (and columns)</param>
        /// <param name="SecRnd">Source of randomness</param>
        private void AssignRandomLowerTriangularMatrix(int N, IRandom SecRnd)
        {
            RowCount = N;
            ColumnCount = N;
            m_length = IntUtils.URShift((N + 31), 5);
            m_matrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);
            for (int i = 0; i < RowCount; i++)
            {
                int q = IntUtils.URShift(i, 5);
                int r = i & 0x1f;
                int s = 31 - r;
                r = 1 << r;

                for (int j = 0; j < q; j++)
                    m_matrix[i][j] = SecRnd.Next();
                
                m_matrix[i][q] = (IntUtils.URShift(SecRnd.Next(), s)) | r;

                for (int j = q + 1; j < m_length; j++)
                    m_matrix[i][j] = 0;
            }

        }

        /// <summary>
        /// Create a nxn random upper triangular matrix
        /// </summary>
        /// 
        /// <param name="N">Number of rows (and columns)</param>
        /// <param name="SecRnd">Source of randomness</param>
        private void AssignRandomUpperTriangularMatrix(int N, IRandom SecRnd)
        {
            RowCount = N;
            ColumnCount = N;
            m_length = IntUtils.URShift((N + 31), 5);
            m_matrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);
            int rest = N & 0x1f;
            int help;

            if (rest == 0)
                help = unchecked((int)0xffffffff);
            else
                help = (1 << rest) - 1;
            
            for (int i = 0; i < RowCount; i++)
            {
                int q = IntUtils.URShift(i, 5);
                int r = i & 0x1f;
                int s = r;
                r = 1 << r;

                for (int j = 0; j < q; j++)
                    m_matrix[i][j] = 0;
                
                m_matrix[i][q] = (SecRnd.Next() << s) | r;

                for (int j = q + 1; j < m_length; j++)
                    m_matrix[i][j] = SecRnd.Next();
                
                m_matrix[i][m_length - 1] &= help;
            }
        }

        /// <summary>
        /// Create an nxn random regular matrix
        /// </summary>
        /// 
        /// <param name="N">Number of rows (and columns)</param>
        /// <param name="SecRnd">Source of randomness</param>
        private void AssignRandomRegularMatrix(int N, IRandom SecRnd)
        {
            RowCount = N;
            ColumnCount = N;
            m_length = IntUtils.URShift((N + 31), 5);
            m_matrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);
            GF2Matrix lm = new GF2Matrix(N, Matrix.MATRIX_TYPE_RANDOM_LT, SecRnd);
            GF2Matrix um = new GF2Matrix(N, Matrix.MATRIX_TYPE_RANDOM_UT, SecRnd);
            GF2Matrix rm = (GF2Matrix)lm.RightMultiply(um);
            Permutation perm = new Permutation(N, SecRnd);
            int[] p = perm.GetVector();

            for (int i = 0; i < N; i++)
                Array.Copy(rm.m_matrix[i], 0, m_matrix[p[i]], 0, m_length);
        }

        /// <summary>
        /// Swap two rows of the given matrix
        /// </summary>
        /// 
        /// <param name="NMatrix">The matrix</param>
        /// <param name="First">The index of the first row</param>
        /// <param name="Second">The index of the second row</param>
        private static void SwapRows(int[][] NMatrix, int First, int Second)
        {
            int[] tmp = NMatrix[First];
            NMatrix[First] = NMatrix[Second];
            NMatrix[Second] = tmp;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Clear()
        {
            if (m_length != 0)
                m_length = 0;
            if (m_matrix != null)
            {
                for (int i = 0; i < m_matrix.Length; i++)
                    Array.Clear(m_matrix[i], 0, m_matrix[i].Length);
            }
        }

        /// <summary>
        /// Compute the transpose of this matrix
        /// </summary>
        /// 
        /// <returns>Returns <c>(this)^T</c></returns>
        public Matrix ComputeTranspose()
        {
            int[][] result = ArrayUtils.CreateJagged<int[][]>(ColumnCount, IntUtils.URShift((RowCount + 31), 5));

            for (int i = 0; i < RowCount; i++)
            {
                if (ParallelUtils.IsParallel)
                {
                    // normalize all other columns
                    Parallel.For(0, ColumnCount, j =>
                    {
                        int qs = IntUtils.URShift(j, 5);
                        int rs = j & 0x1f;
                        int b = (IntUtils.URShift(m_matrix[i][qs], rs)) & 1;
                        int qt = IntUtils.URShift(i, 5);
                        int rt = i & 0x1f;
                        if (b == 1)
                        {
                            lock (result)
                                result[j][qt] |= 1 << rt;
                        }
                    });
                }
                else
                {
                    for (int j = 0; j < ColumnCount; j++)
                    {
                        int qs = IntUtils.URShift(j, 5);
                        int rs = j & 0x1f;
                        int b = (IntUtils.URShift(m_matrix[i][qs], rs)) & 1;
                        int qt = IntUtils.URShift(i, 5);
                        int rt = i & 0x1f;
                        if (b == 1)
                            result[j][qt] |= 1 << rt;
                    }
                }
            }

            return new GF2Matrix(RowCount, result);
        }

        /// <summary>
        /// Create a nxn random regular matrix and its inverse
        /// </summary>
        /// 
        /// <param name="N">Number of rows (and columns)</param>
        /// <param name="SecRnd">Source of randomness</param>
        /// <returns>The created random regular matrix and its inverse</returns>
        public static GF2Matrix[] CreateRandomRegularMatrixAndItsInverse(int N, IRandom SecRnd)
        {
            GF2Matrix[] result = new GF2Matrix[2];

            // First part: create regular matrix
            int length = (N + 31) >> 5;
            GF2Matrix lm = new GF2Matrix(N, Matrix.MATRIX_TYPE_RANDOM_LT, SecRnd);
            GF2Matrix um = new GF2Matrix(N, Matrix.MATRIX_TYPE_RANDOM_UT, SecRnd);
            GF2Matrix rm = (GF2Matrix)lm.RightMultiply(um);
            Permutation p = new Permutation(N, SecRnd);
            int[] pVec = p.GetVector();

            int[][] matrix = ArrayUtils.CreateJagged<int[][]>(N, length);
            for (int i = 0; i < N; i++)
                Array.Copy(rm.m_matrix[pVec[i]], 0, matrix[i], 0, length);

            result[0] = new GF2Matrix(N, matrix);

            // Second part: create inverse matrix
            // inverse to lm
            GF2Matrix invLm = new GF2Matrix(N, Matrix.MATRIX_TYPE_UNIT);
            for (int i = 0; i < N; i++)
            {
                int rest = i & 0x1f;
                int q = IntUtils.URShift(i, 5);
                int r = 1 << rest;
                for (int j = i + 1; j < N; j++)
                {
                    int b = (lm.m_matrix[j][q]) & r;
                    if (b != 0)
                    {
                        for (int k = 0; k <= q; k++)
                            invLm.m_matrix[j][k] ^= invLm.m_matrix[i][k];
                    }
                }
            }
            // inverse to um
            GF2Matrix invUm = new GF2Matrix(N, Matrix.MATRIX_TYPE_UNIT);
            for (int i = N - 1; i >= 0; i--)
            {
                int rest = i & 0x1f;
                int q = IntUtils.URShift(i, 5);
                int r = 1 << rest;
                for (int j = i - 1; j >= 0; j--)
                {
                    int b = (um.m_matrix[j][q]) & r;
                    if (b != 0)
                    {
                        for (int k = q; k < length; k++)
                            invUm.m_matrix[j][k] ^= invUm.m_matrix[i][k];
                    }
                }
            }

            // inverse matrix
            result[1] = (GF2Matrix)invUm.RightMultiply(invLm.RightMultiply(p));

            return result;
        }

        /// <summary>
        /// Compute the full form matrix <c>(this | Id)</c> from this matrix in left compact form.
        /// <para>Where <c>Id</c> is the <c>k x k</c> identity matrix and <c>k</c> is the number of rows of this matrix.</para>
        /// </summary>
        /// 
        /// <returns>Returns <c>(this | Id)</c></returns>
        public GF2Matrix ExtendLeftCompactForm()
        {
            int newNumColumns = ColumnCount + RowCount;
            GF2Matrix result = new GF2Matrix(RowCount, newNumColumns);
            int ind = RowCount - 1 + ColumnCount;

            for (int i = RowCount - 1; i >= 0; i--, ind--)
            {
                // copy this matrix to first columns
                Array.Copy(m_matrix[i], 0, result.m_matrix[i], 0, m_length);
                // store the identity in last columns
                result.m_matrix[i][ind >> 5] |= 1 << (ind & 0x1f);
            }

            return result;
        }

        /// <summary>
        /// Compute the full form matrix <c>(Id | this)</c> from this matrix in right compact form.
        /// <para>Where <c>Id</c> is the <c>k x k</c> identity matrix and <c>k</c> is the number of rows of this matrix.</para>
        /// </summary>
        /// 
        /// <returns>Returns <c>(Id | this)</c></returns>
        public GF2Matrix ExtendRightCompactForm()
        {
            GF2Matrix result = new GF2Matrix(RowCount, RowCount + ColumnCount);

            int q = RowCount >> 5;
            int r = RowCount & 0x1f;

            for (int i = RowCount - 1; i >= 0; i--)
            {
                // store the identity in first columns
                result.m_matrix[i][i >> 5] |= 1 << (i & 0x1f);

                // copy this matrix to last columns if words have to be shifted
                if (r != 0)
                {
                    int ind = q;
                    // process all but last word
                    for (int j = 0; j < m_length - 1; j++)
                    {
                        // obtain matrix word
                        int mw = m_matrix[i][j];
                        // shift to correct position
                        result.m_matrix[i][ind++] |= mw << r;
                        result.m_matrix[i][ind] |= IntUtils.URShift(mw, (32 - r));
                    }

                    // process last word
                    int mwv = m_matrix[i][m_length - 1];
                    result.m_matrix[i][ind++] |= mwv << r;
                    if (ind < result.m_length)
                        result.m_matrix[i][ind] |= IntUtils.URShift(mwv, (32 - r));
                }
                else
                {
                    // no shifting necessary
                    Array.Copy(m_matrix[i], 0, result.m_matrix[i], q, m_length);
                }
            }

            return result;
        }

        /// <summary>
        /// Returns the percentage of the number of "ones" in this matrix
        /// </summary>
        /// 
        /// <returns>The Hamming weight of this matrix (as a ratio).</returns>
        public double HammingWeight()
        {
            double counter = 0.0;
            double elementCounter = 0.0;
            int rest = ColumnCount & 0x1f;
            int d;

            if (rest == 0)
                d = m_length;
            else
                d = m_length - 1;

            for (int i = 0; i < RowCount; i++)
            {
                for (int j = 0; j < d; j++)
                {
                    int a = m_matrix[i][j];
                    for (int k = 0; k < 32; k++)
                    {
                        int b = (IntUtils.URShift(a, k)) & 1;
                        counter = counter + b;
                        elementCounter = elementCounter + 1;
                    }
                }
                int a1 = m_matrix[i][m_length - 1];
                for (int k = 0; k < rest; k++)
                {
                    int b = (IntUtils.URShift(a1, k)) & 1;
                    counter = counter + b;
                    elementCounter = elementCounter + 1;
                }
            }

            return counter / elementCounter;
        }

        /// <summary>
        /// Compute the product of a permutation matrix (which is generated from an n-permutation) and this matrix.
        /// </summary>
        /// 
        /// <param name="P">The permutation</param>
        /// 
        /// <returns>Returns GF2Matrix <c>P*this</c></returns>
        public Matrix LeftMultiply(Permutation P)
        {
            int[] pVec = P.GetVector();

            if (pVec.Length != RowCount)
                throw new ArithmeticException("GF2Matrix: length mismatch!");

            int[][] result = new int[RowCount][];

            for (int i = RowCount - 1; i >= 0; i--)
                result[i] = IntUtils.DeepCopy(m_matrix[pVec[i]]);

            return new GF2Matrix(RowCount, result);
        }

        /// <summary>
        /// Compute the product of the matrix <c>(this | Id)</c> and a column vector.
        /// <para>Where <c>Id</c> is a <c>(numRows x numRows)</c> unit matrix.</para>
        /// </summary>
        /// 
        /// <param name="V">The vector over GF(2)</param>
        /// 
        /// <returns>Returns <c>(this | Id)*vector</c></returns>
        public Vector LeftMultiplyLeftCompactForm(Vector V)
        {
            if (!(V is GF2Vector))
                throw new ArithmeticException("GF2Matrix: Vector is not defined over GF(2)!");
            if (V.Length != RowCount)
                throw new ArithmeticException("GF2Matrix: Length mismatch!");

            int[] v = ((GF2Vector)V).VectorArray;
            int[] res = new int[IntUtils.URShift((RowCount + ColumnCount + 31), 5)];
            int words = IntUtils.URShift(RowCount, 5);
            int row = 0;

            // process full words of vector
            for (int i = 0; i < words; i++)
            {
                int bitMask = 1;
                do
                {
                    int b = v[i] & bitMask;
                    if (b != 0)
                    {
                        // compute scalar product part
                        for (int j = 0; j < m_length; j++)
                            res[j] ^= m_matrix[row][j];
                        // set last bit
                        int q = IntUtils.URShift((ColumnCount + row), 5);
                        int r = (ColumnCount + row) & 0x1f;
                        res[q] |= 1 << r;
                    }
                    row++;
                    bitMask <<= 1;
                }
                while (bitMask != 0);
            }

            // process last word of vector
            int rem = 1 << (RowCount & 0x1f);
            int bitMask2 = 1;
            while (bitMask2 != rem)
            {
                int b = v[words] & bitMask2;
                if (b != 0)
                {
                    // compute scalar product part
                    for (int j = 0; j < m_length; j++)
                        res[j] ^= m_matrix[row][j];
                    // set last bit
                    int q = IntUtils.URShift((ColumnCount + row), 5);
                    int r = (ColumnCount + row) & 0x1f;
                    res[q] |= 1 << r;
                }
                row++;
                bitMask2 <<= 1;
            }

            return new GF2Vector(res, RowCount + ColumnCount);
        }

        /// <summary>
        /// Get the quadratic submatrix of this matrix consisting of the leftmost <c>numRows</c> columns
        /// </summary>
        /// 
        /// <returns>Returns the <c>(numRows x numRows)</c> submatrix</returns>
        public GF2Matrix LeftSubMatrix()
        {
            if (ColumnCount <= RowCount)
                throw new ArithmeticException("GF2Matrix: empty submatrix!");

            int length = (RowCount + 31) >> 5;
            int[][] result = ArrayUtils.CreateJagged<int[][]>(RowCount, length);
            int bitMask = (1 << (RowCount & 0x1f)) - 1;
            if (bitMask == 0)
                bitMask = -1;
            
            for (int i = RowCount - 1; i >= 0; i--)
            {
                Array.Copy(m_matrix[i], 0, result[i], 0, length);
                result[i][length - 1] &= bitMask;
            }

            return new GF2Matrix(RowCount, result);
        }

        /// <summary>
        /// Compute the product of the matrix <c>(Id | this)</c> and a column vector, where <c>Id</c> is a <c>(numRows x numRows)</c> unit matrix.
        /// </summary>
        /// 
        /// <param name="V">The vector over GF(2)</param>
        /// 
        /// <returns>Returns <c>(Id | this)*vector</c></returns>
        public Vector RightMultiplyRightCompactForm(Vector V)
        {
            if (!(V is GF2Vector))
                throw new ArithmeticException("GF2Matrix: Vector is not defined over GF(2)!");
            if (V.Length != ColumnCount + RowCount)
                throw new ArithmeticException("GF2Matrix: Length mismatch!");

            int[] v = ((GF2Vector)V).VectorArray;
            int[] res = new int[IntUtils.URShift((RowCount + 31), 5)];
            int q = RowCount >> 5;
            int r = RowCount & 0x1f;

            // for all rows
            for (int i = 0; i < RowCount; i++)
            {
                // get vector bit
                int help = (IntUtils.URShift(v[i >> 5], (i & 0x1f)) & 1);

                // compute full word scalar products
                int vInd = q;
                // if words have to be shifted
                if (r != 0)
                {
                    int vw = 0;
                    // process all but last word
                    for (int j = 0; j < m_length - 1; j++)
                    {
                        // shift to correct position
                        vw = (IntUtils.URShift(v[vInd++], r)) | (v[vInd] << (32 - r));
                        help ^= m_matrix[i][j] & vw;
                    }
                    // process last word
                    vw = IntUtils.URShift(v[vInd++], r);
                    if (vInd < v.Length)
                        vw |= v[vInd] << (32 - r);
                    help ^= m_matrix[i][m_length - 1] & vw;
                }
                else
                {
                    // no shifting necessary
                    for (int j = 0; j < m_length; j++)
                        help ^= m_matrix[i][j] & v[vInd++];
                }

                // compute single word scalar product
                int bitValue = 0;
                for (int j = 0; j < 32; j++)
                {
                    bitValue ^= help & 1;
                    help = IntUtils.URShift(help, 1);
                }

                // set result bit
                if (bitValue == 1)
                    res[i >> 5] |= 1 << (i & 0x1f);
            }

            return new GF2Vector(res, RowCount);
        }

        /// <summary>
        /// Get the submatrix of this matrix consisting of the rightmost <c>numColumns-numRows</c> columns
        /// </summary>
        /// 
        /// <returns>Returns the <c>(numRows x (numColumns-numRows))</c> submatrix</returns>
        public GF2Matrix RightSubMatrix()
        {
            if (ColumnCount <= RowCount)
                throw new ArithmeticException("GF2Matrix: empty submatrix!");

            int q = RowCount >> 5;
            int r = RowCount & 0x1f;
            GF2Matrix result = new GF2Matrix(RowCount, ColumnCount - RowCount);

            for (int i = RowCount - 1; i >= 0; i--)
            {
                // if words have to be shifted
                if (r != 0)
                {
                    int ind = q;
                    // process all but last word and shift to correct position
                    for (int j = 0; j < result.m_length - 1; j++)
                        result.m_matrix[i][j] = (IntUtils.URShift(m_matrix[i][ind++], r)) | (m_matrix[i][ind] << (32 - r));

                    // process last word
                    result.m_matrix[i][result.m_length - 1] = IntUtils.URShift(m_matrix[i][ind++], r);
                    if (ind < m_length)
                        result.m_matrix[i][result.m_length - 1] |= m_matrix[i][ind] << (32 - r);
                }
                else
                {
                    // no shifting necessary
                    Array.Copy(m_matrix[i], q, result.m_matrix[i], 0, result.m_length);
                }
            }

            return result;
        }

        /// <summary>
        /// Return the row of this matrix with the given index
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        /// 
        /// <returns>The row of this matrix with the given index</returns>
        public int[] RowAtIndex(int Index)
        {
            return m_matrix[Index];
        }

        /// <summary>
        /// Get the matrix array
        /// </summary>
        /// 
        /// <returns>The matrix array</returns>
        public int[][] ToIntArray()
        {
            return m_matrix;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compute the inverse of this matrix
        /// </summary>
        /// 
        /// <returns>Returns the inverse of this matrix</returns>
        public override Matrix ComputeInverse()
        {
            if (RowCount != ColumnCount)
                throw new ArithmeticException("GF2Matrix: Matrix is not invertible!");

            // clone this matrix
            int[][] tmpMatrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);
            for (int i = RowCount - 1; i >= 0; i--)
                tmpMatrix[i] = IntUtils.DeepCopy(m_matrix[i]);

            // initialize inverse matrix as unit matrix
            int[][] invMatrix = ArrayUtils.CreateJagged<int[][]>(RowCount, m_length);
            for (int i = RowCount - 1; i >= 0; i--)
            {
                int q = i >> 5;
                int r = i & 0x1f;
                invMatrix[i][q] = 1 << r;
            }

            // simultaneously compute Gaussian reduction of tmpMatrix and unit matrix
            for (int i = 0; i < RowCount; i++)
            {
                int q = i >> 5;
                int bitMask = 1 << (i & 0x1f);
                // if diagonal element is zero
                if ((tmpMatrix[i][q] & bitMask) == 0)
                {
                    bool foundNonZero = false;
                    // find a non-zero element in the same column
                    for (int j = i + 1; j < RowCount; j++)
                    {
                        if ((tmpMatrix[j][q] & bitMask) != 0)
                        {
                            // found it, swap rows ...
                            foundNonZero = true;
                            SwapRows(tmpMatrix, i, j);
                            SwapRows(invMatrix, i, j);
                            // ... and quit searching
                            j = RowCount;

                            continue;
                        }
                    }
                    // if no non-zero element was found the matrix is not invertible
                    if (!foundNonZero)
                        throw new ArithmeticException("GF2Matrix: Matrix is not invertible!");
                }

                // normalize all but i-th row
                for (int j = RowCount - 1; j >= 0; j--)
                {
                    if ((j != i) && ((tmpMatrix[j][q] & bitMask) != 0))
                    {
                        AddToRow(tmpMatrix[i], tmpMatrix[j], q);
                        AddToRow(invMatrix[i], invMatrix[j], 0);
                    }
                }
            }

            return new GF2Matrix(ColumnCount, invMatrix);
        }

        /// <summary>
        /// Compare this matrix with another object.
        /// </summary>
        /// 
        /// <param name="Obj">The object to compare this to</param>
        /// <returns>Returns <c>true</c> if object is equal and has the same values</returns>
        public override bool Equals(Object Obj)
        {
            if (!(Obj is GF2Matrix))
                return false;
            
            GF2Matrix otherMatrix = (GF2Matrix)Obj;

            if ((RowCount != otherMatrix.RowCount) || (ColumnCount != otherMatrix.ColumnCount) || (m_length != otherMatrix.m_length))
                return false;

            for (int i = 0; i < RowCount; i++)
            {
                if (!Compare.IsEqual(m_matrix[i], otherMatrix.m_matrix[i]))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns encoded matrix, i.e., this matrix in byte array form
        /// </summary>
        /// 
        /// <returns>The encoded matrix</returns>
        public override byte[] GetEncoded()
        {
            int n = IntUtils.URShift((ColumnCount + 7), 3);
            n *= RowCount;
            n += 8;
            byte[] enc = new byte[n];

            LittleEndian.IntToOctets(RowCount, enc, 0);
            LittleEndian.IntToOctets(ColumnCount, enc, 4);
            // number of "full" integer
            int q = IntUtils.URShift(ColumnCount, 5);
            // number of bits in non-full integer
            int r = ColumnCount & 0x1f;
            int count = 8;

            for (int i = 0; i < RowCount; i++)
            {
                for (int j = 0; j < q; j++, count += 4)
                    LittleEndian.IntToOctets(m_matrix[i][j], enc, count);
                for (int j = 0; j < r; j += 8)
                    enc[count++] = (byte)((IntUtils.URShift(m_matrix[i][q], j)) & 0xff);
            }

            return enc;
        }

        /// <summary>
        /// Computes the the hash code of this matrix
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = RowCount * 31 + ColumnCount * 31 + m_length * 31;
            hash += ArrayUtils.GetHashCode(m_matrix);

            return hash;
        }

        /// <summary>
        /// Check if this is the zero matrix (i.e., all entries are zero).
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if this is the zero matrix</returns>
        public override bool IsZero()
        {
            for (int i = 0; i < RowCount; i++)
            {
                for (int j = 0; j < m_length; j++)
                {
                    if (m_matrix[i][j] != 0)
                        return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Compute product a row vector and this matrix
        /// </summary>
        /// 
        /// <param name="V">A vector over GF(2)</param>
        /// <returns>Vector product <c>v*matrix</c></returns>
        public override Vector LeftMultiply(Vector V)
        {
            if (!(V is GF2Vector))
                throw new ArithmeticException("vector is not defined over GF(2)");

            if (V.Length != RowCount)
                throw new ArithmeticException("GF2Matrix: length mismatch!");

            int[] v = ((GF2Vector)V).VectorArray;
            int[] res = new int[m_length];
            int q = RowCount >> 5;
            int r = 1 << (RowCount & 0x1f);

            // compute scalar products with full words of vector
            int row = 0;
            for (int i = 0; i < q; i++)
            {
                int bitMask = 1;
                do
                {
                    int b = v[i] & bitMask;
                    if (b != 0)
                    {
                        for (int j = 0; j < m_length; j++)
                            res[j] ^= m_matrix[row][j];
                    }
                    row++;
                    bitMask <<= 1;
                }
                while (bitMask != 0);
            }

            // compute scalar products with last word of vector
            int bitMask2 = 1;
            while (bitMask2 != r)
            {
                int b = v[q] & bitMask2;
                if (b != 0)
                {
                    for (int j = 0; j < m_length; j++)
                        res[j] ^= m_matrix[row][j];
                }
                row++;
                bitMask2 <<= 1;
            }

            return new GF2Vector(res, ColumnCount);
        }

        /// <summary>
        /// Compute the product of this matrix and a matrix A over GF(2)
        /// </summary>
        /// 
        /// <param name="M">A matrix A over GF(2)</param>
        /// 
        /// <returns>Returns matrix product <c>this*M</c></returns>
        public override Matrix RightMultiply(Matrix M)
        {
            if (!(M is GF2Matrix))
                throw new ArithmeticException("GF2Matrix: Matrix is not defined over GF(2)!");
            if (M.RowCount != ColumnCount)
                throw new ArithmeticException("GF2Matrix: Length mismatch!");

            GF2Matrix a = (GF2Matrix)M;
            GF2Matrix result = new GF2Matrix(RowCount, M.ColumnCount);

            int d;
            int rest = ColumnCount & 0x1f;
            if (rest == 0)
                d = m_length;
            else
                d = m_length - 1;

            for (int i = 0; i < RowCount; i++)
            {
                int count = 0;
                for (int j = 0; j < d; j++)
                {
                    int e = m_matrix[i][j];
                    for (int h = 0; h < 32; h++)
                    {
                        int b = e & (1 << h);
                        if (b != 0)
                        {
                            for (int g = 0; g < a.m_length; g++)
                                result.m_matrix[i][g] ^= a.m_matrix[count][g];
                        }
                        count++;
                    }
                }
                int e1 = m_matrix[i][m_length - 1];
                for (int h = 0; h < rest; h++)
                {
                    int b = e1 & (1 << h);
                    if (b != 0)
                    {
                        for (int g = 0; g < a.m_length; g++)
                            result.m_matrix[i][g] ^= a.m_matrix[count][g];
                    }
                    count++;
                }
            }

            return result;
        }

        /// <summary>
        /// Compute the product of this matrix and a permutation matrix which is generated from an n-permutation
        /// </summary>
        /// 
        /// <param name="P">The permutation</param>
        /// 
        /// <returns>Returns GF2Matrix <c>this*P</c></returns>
        public override Matrix RightMultiply(Permutation P)//3
        {

            int[] pVec = P.GetVector();
            if (pVec.Length != ColumnCount)
                throw new ArithmeticException("GF2Matrix: Length mismatch!");

            GF2Matrix result = new GF2Matrix(RowCount, ColumnCount);

            for (int i = ColumnCount - 1; i >= 0; i--)
            {
                int q = IntUtils.URShift(i, 5);
                int r = i & 0x1f;
                int pq = IntUtils.URShift(pVec[i], 5);
                int pr = pVec[i] & 0x1f;

                for (int j = RowCount - 1; j >= 0; j--)
                    result.m_matrix[j][q] |= ((IntUtils.URShift(m_matrix[j][pq], pr)) & 1) << r;
            }

            return result;
        }

        /// <summary>
        /// Compute the product of this matrix and the given column vector
        /// </summary>
        /// 
        /// <param name="V">The vector over GF(2)</param>
        /// 
        /// <returns>Returns <c>this*vector</c></returns>
        public override Vector RightMultiply(Vector V)
        {
            if (!(V is GF2Vector))
                throw new ArithmeticException("GF2Matrix: Vector is not defined over GF(2)!");
            if (V.Length != ColumnCount)
                throw new ArithmeticException("GF2Matrix: Length mismatch!");

            int[] v = ((GF2Vector)V).VectorArray;
            int[] res = new int[IntUtils.URShift((RowCount + 31), 5)];

            for (int i = 0; i < RowCount; i++)
            {
                // compute full word scalar products
                int help = 0;
                for (int j = 0; j < m_length; j++)
                    help ^= m_matrix[i][j] & v[j];
                // compute single word scalar product
                int bitValue = 0;
                for (int j = 0; j < 32; j++)
                    bitValue ^= (IntUtils.URShift(help, j)) & 1;
                // set result bit
                if (bitValue == 1)
                    res[IntUtils.URShift(i, 5)] |= 1 << (i & 0x1f);
            }

            return new GF2Vector(res, RowCount);
        }

        /// <summary>
        /// Get a human readable form of the matrix
        /// </summary>
        /// 
        /// <returns>Returns the matrix as a string</returns>
        public override String ToString()
        {
            int rest = ColumnCount & 0x1f;
            int d;

            if (rest == 0)
                d = m_length;
            else
                d = m_length - 1;

            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < RowCount; i++)
            {
                buf.Append(i + ": ");
                for (int j = 0; j < d; j++)
                {
                    int a = m_matrix[i][j];
                    for (int k = 0; k < 32; k++)
                    {
                        int b = (IntUtils.URShift(a, k)) & 1;
                        if (b == 0)
                            buf.Append('0');
                        else
                            buf.Append('1');
                    }
                    buf.Append(' ');
                }
                int a2 = m_matrix[i][m_length - 1];
                for (int k = 0; k < rest; k++)
                {
                    int b = (IntUtils.URShift(a2, k)) & 1;
                    if (b == 0)
                        buf.Append('0');
                    else
                        buf.Append('1');
                }
                buf.Append('\n');
            }

            return buf.ToString();
        }
        #endregion
    }
}
