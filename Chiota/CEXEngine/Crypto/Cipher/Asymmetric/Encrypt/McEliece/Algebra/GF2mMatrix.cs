#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class describes some operations with matrices over finite field <c>GF(2^m)</c> with small <c>m</c> (1&lt; m &lt;32)
    /// </summary>
    internal class GF2mMatrix : Matrix
    {
        #region Fields
        /// <summary>
        /// The finite field GF(2^m)
        /// </summary>
        protected GF2mField FieldG;
        /// <summary>
        /// For the matrix representation the array of type int[][] is used, thus every element of the 
        /// array keeps one element of the matrix (element from finite field GF(2^m))
        /// </summary>
        protected int[][] MatrixN;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialze this class with an encoded matrix
        /// </summary>
        /// 
        /// <param name="FieldG">The finite field GF(2^m)</param>
        /// <param name="Encoded">The matrix in byte array form</param>
        public GF2mMatrix(GF2mField FieldG, byte[] Encoded)
        {
            this.FieldG = FieldG;
            int d = 8;
            int count = 1;

            while (FieldG.Degree > d)
            {
                count++;
                d += 8;
            }

            if (Encoded.Length < 5)
                throw new ArgumentException("GF2mMatrix: Given array is not encoded matrix over GF(2^m)!");

            this.RowCount = ((Encoded[3] & 0xff) << 24) ^ ((Encoded[2] & 0xff) << 16) ^ ((Encoded[1] & 0xff) << 8) ^ (Encoded[0] & 0xff);
            int n = count * this.RowCount;

            if ((this.RowCount <= 0) || (((Encoded.Length - 4) % n) != 0))
                throw new ArgumentException("GF2mMatrix: Given array is not encoded matrix over GF(2^m)!");

            this.ColumnCount = (Encoded.Length - 4) / n;
            MatrixN = ArrayUtils.CreateJagged<int[][]>(this.RowCount, this.ColumnCount);
            count = 4;

            for (int i = 0; i < this.RowCount; i++)
            {
                for (int j = 0; j < this.ColumnCount; j++)
                {
                    for (int k = 0; k < d; k += 8)
                        MatrixN[i][j] ^= (Encoded[count++] & 0x000000ff) << k;
                    
                    if (!this.FieldG.IsElementOfThisField(MatrixN[i][j]))
                        throw new ArgumentException("GF2mMatrix: Given array is not encoded matrix over GF(2^m)!");
                }
            }
        }

        /// <summary>
        /// Create an instance using values from another GF2mMatrix instance
        /// </summary>
        /// 
        /// <param name="G">The GF2mMatrix instance</param>
        public GF2mMatrix(GF2mMatrix G)
        {
            RowCount = G.RowCount;
            ColumnCount = G.ColumnCount;
            FieldG = G.FieldG;
            MatrixN = new int[RowCount][];

            for (int i = 0; i < RowCount; i++)
                MatrixN[i] = IntUtils.DeepCopy(G.MatrixN[i]);
        }

        /// <summary>
        /// Create an instance using values from a field and matrix
        /// </summary>
        /// 
        /// <param name="FieldG">A finite field GF(2^m)</param>
        /// <param name="MatrixN">The matrix as int array; only the reference is copied.</param>
        protected GF2mMatrix(GF2mField FieldG, int[][] MatrixN)
        {
            this.FieldG = FieldG;
            this.MatrixN = MatrixN;
            RowCount = MatrixN.Length;
            ColumnCount = MatrixN[0].Length;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compute the inverse of this matrix
        /// </summary>
        /// 
        /// <returns>Returns the inverse of this matrix (newly created)</returns>
        public override Matrix ComputeInverse()
        {
            if (RowCount != ColumnCount)
                throw new ArithmeticException("GF2mMatrix: Matrix is not invertible!");

            // clone this matrix
            int[][] tmpMatrix = ArrayUtils.CreateJagged<int[][]>(RowCount, RowCount);
            for (int i = RowCount - 1; i >= 0; i--)
                tmpMatrix[i] = IntUtils.DeepCopy(MatrixN[i]);

            // initialize inverse matrix as unit matrix
            int[][] invMatrix = ArrayUtils.CreateJagged<int[][]>(RowCount, RowCount);
            for (int i = RowCount - 1; i >= 0; i--)
                invMatrix[i][i] = 1;

            // simultaneously compute Gaussian reduction of tmpMatrix and unit
            // matrix
            for (int i = 0; i < RowCount; i++)
            {
                // if diagonal element is zero
                if (tmpMatrix[i][i] == 0)
                {
                    bool foundNonZero = false;
                    // find a non-zero element in the same column
                    for (int j = i + 1; j < RowCount; j++)
                    {
                        if (tmpMatrix[j][i] != 0)
                        {
                            // found it, swap rows ...
                            foundNonZero = true;
                            SwapColumns(tmpMatrix, i, j);
                            SwapColumns(invMatrix, i, j);
                            // ... and quit searching
                            j = RowCount;
                            continue;
                        }
                    }
                    // if no non-zero element was found the matrix is not invertible
                    if (!foundNonZero)
                        throw new ArithmeticException("GF2mMatrix: Matrix is not invertible!");
                }

                // normalize i-th row
                int coef = tmpMatrix[i][i];
                int invCoef = FieldG.Inverse(coef);
                MultRowWithElementThis(tmpMatrix[i], invCoef);
                MultRowWithElementThis(invMatrix[i], invCoef);

                // normalize all other rows
                for (int j = 0; j < RowCount; j++)
                {
                    if (j != i)
                    {
                        coef = tmpMatrix[j][i];
                        if (coef != 0)
                        {
                            int[] tmpRow = MultRowWithElement(tmpMatrix[i], coef);
                            int[] tmpInvRow = MultRowWithElement(invMatrix[i], coef);
                            AddToRow(tmpRow, tmpMatrix[j]);
                            AddToRow(tmpInvRow, invMatrix[j]);
                        }
                    }
                }
            }

            return new GF2mMatrix(FieldG, invMatrix);
        }

        /// <summary>
        /// Checks if given object is equal to this matrix. The method returns false whenever the given object is not a matrix over GF(2^m)
        /// </summary>
        /// 
        /// <param name="Obj">The object to compare to this</param>
        /// 
        /// <returns>Returns <c>true</c> if the object is equal</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is GF2mMatrix))
                return false;

            GF2mMatrix otherMatrix = (GF2mMatrix)Obj;

            if ((!this.FieldG.Equals(otherMatrix.FieldG)) || (otherMatrix.RowCount != this.ColumnCount) || (otherMatrix.ColumnCount != this.ColumnCount))
                return false;

            for (int i = 0; i < this.RowCount; i++)
            {
                for (int j = 0; j < this.ColumnCount; j++)
                {
                    if (this.MatrixN[i][j] != otherMatrix.MatrixN[i][j])
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Returns a byte array encoding of this matrix
        /// </summary>
        /// 
        /// <returns>The encoded GF2mMatrix</returns>
        public override byte[] GetEncoded()
        {
            int d = 8;
            int count = 1;
            while (FieldG.Degree > d)
            {
                count++;
                d += 8;
            }

            byte[] bf = new byte[this.RowCount * this.ColumnCount * count + 4];
            bf[0] = (byte)(this.RowCount & 0xff);
            bf[1] = (byte)((this.RowCount >> 8) & 0xff);
            bf[2] = (byte)((this.RowCount >> 16) & 0xff);
            bf[3] = (byte)((this.RowCount >> 24) & 0xff);

            count = 4;
            for (int i = 0; i < this.RowCount; i++)
            {
                for (int j = 0; j < this.ColumnCount; j++)
                {
                    for (int jj = 0; jj < d; jj += 8)
                        bf[count++] = (byte)(IntUtils.URShift(MatrixN[i][j], jj));
                }
            }

            return bf;
        }

        /// <summary>
        /// Computes the the hash code of this matrix
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = FieldG.GetHashCode() + RowCount * 31 + ColumnCount * 31;
            hash += ArrayUtils.GetHashCode(MatrixN);

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
                for (int j = 0; j < ColumnCount; j++)
                {
                    if (MatrixN[i][j] != 0)
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Not implemented
        /// </summary>
        /// 
        /// <param name="V">Vector V</param>
        /// 
        /// <returns>throws NotImplementedException</returns>
        public override Vector LeftMultiply(Vector V)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Not implemented
        /// </summary>
        /// 
        /// <param name="M">Matrix M</param>
        /// 
        /// <returns>throws NotImplementedException</returns>
        public override Matrix RightMultiply(Matrix M)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Not implemented
        /// </summary>
        /// 
        /// <param name="P">Permutation P</param>
        /// 
        /// <returns>throws NotImplementedException</returns>
        public override Matrix RightMultiply(Permutation P)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Not implemented
        /// </summary>
        /// 
        /// <param name="V">Vector V</param>
        /// 
        /// <returns>throws NotImplementedException</returns>
        public override Vector RightMultiply(Vector V)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Get a human readable form of the matrix
        /// </summary>
        /// 
        /// <returns>Returns the matrix as a string</returns>
        public override String ToString()
        {
            String str = this.RowCount + " x " + this.ColumnCount + " Matrix over " + this.FieldG.ToString() + ": \n";

            for (int i = 0; i < this.RowCount; i++)
            {
                for (int j = 0; j < this.ColumnCount; j++)
                    str = str + this.FieldG.ElementToString(MatrixN[i][j]) + " : ";
                
                str = str + "\n";
            }

            return str;
        }
        #endregion

        #region Private Methods
        private static void SwapColumns(int[][] M, int First, int Second)
        {
            int[] tmp = M[First];
            M[First] = M[Second];
            M[Second] = tmp;
        }

        private void MultRowWithElementThis(int[] Row, int Element)
        {
            for (int i = Row.Length - 1; i >= 0; i--)
                Row[i] = FieldG.Multiply(Row[i], Element);
        }

        private int[] MultRowWithElement(int[] Row, int Element)
        {
            int[] result = new int[Row.Length];
            for (int i = Row.Length - 1; i >= 0; i--)
                result[i] = FieldG.Multiply(Row[i], Element);
            
            return result;
        }

        private void AddToRow(int[] FromRow, int[] ToRow)
        {
            for (int i = ToRow.Length - 1; i >= 0; i--)
                ToRow[i] = FieldG.Add(FromRow[i], ToRow[i]);
        }
        #endregion
    }
}
