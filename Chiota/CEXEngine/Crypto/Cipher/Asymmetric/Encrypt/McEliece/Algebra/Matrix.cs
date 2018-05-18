#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This abstract class defines matrices.
    /// <para>It holds the number of rows and the number of columns of the matrix and defines some basic methods.</para>
    /// </summary>
    internal abstract class Matrix
    {
        #region Constants
        /// <summary>
        /// Zero matrix
        /// </summary>
        public const char MATRIX_TYPE_ZERO = 'Z';
        /// <summary>
        /// Unit matrix
        /// </summary>
        public const char MATRIX_TYPE_UNIT = 'I';
        /// <summary>
        /// Random lower triangular matrix
        /// </summary>
        public const char MATRIX_TYPE_RANDOM_LT = 'L';
        /// <summary>
        /// Random upper triangular matrix
        /// </summary>
        public const char MATRIX_TYPE_RANDOM_UT = 'U';
        /// <summary>
        /// Random regular matrix
        /// </summary>
        public const char MATRIX_TYPE_RANDOM_REGULAR = 'R';
        #endregion

        #region Fields
        /// <summary>
        /// Number of columns
        /// </summary>
        protected int m_columnCount;
        /// <summary>
        /// Number of rows
        /// </summary>
        protected int m_rowCount;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the number of columns in the binary matrix
        /// </summary>
        public int ColumnCount
        {
            get { return m_columnCount; }
            set { m_columnCount = value; }
        }

        /// <summary>
        /// Get: Returns the number of rows in the matrix
        /// </summary>
        public int RowCount
        {
            get { return m_rowCount; }
            set { m_rowCount = value; }
        }
        #endregion

        #region Abstract Methods
        /// <summary>
        /// Compute the inverse of this matrix
        /// </summary>
        /// 
        /// <returns>Returns the inverse of this matrix</returns>
        public abstract Matrix ComputeInverse();

        /// <summary>
        /// Get a copy of the encoded matrix as a byte array
        /// </summary>
        /// 
        /// <returns>Returns this matrix in byte array form</returns>
        public abstract byte[] GetEncoded();

        /// <summary>
        /// Check if this is the zero matrix (i.e., all entries are zero).
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if this is the zero matrix</returns>
        public abstract bool IsZero();

        /// <summary>
        /// Compute the product of a vector and this matrix.
        /// <para>If the length of the vector is greater than the number of rows of this matrix, 
        /// the matrix is multiplied by each m-bit part of the vector.</para>
        /// </summary>
        /// 
        /// <param name="V">A vector</param>
        /// 
        /// <returns>Returns <c>V * this</c></returns>
        public abstract Vector LeftMultiply(Vector V);

        /// <summary>
        /// Compute the product of this matrix and another matrix
        /// </summary>
        /// 
        /// <param name="M">The other matrix</param>
        /// 
        /// <returns>Returns <c>this * M</c></returns>
        public abstract Matrix RightMultiply(Matrix M);

        /// <summary>
        /// Compute the product of this matrix and a permutation
        /// </summary>
        /// 
        /// <param name="P">The permutation</param>
        /// 
        /// <returns>Returns <c>this * P</c></returns>
        public abstract Matrix RightMultiply(Permutation P);

        /// <summary>
        /// Compute the product of this matrix and a vector
        /// </summary>
        /// 
        /// <param name="V">A vector</param>
        /// 
        /// <returns>Returns <c>this * V</c> </returns>
        public abstract Vector RightMultiply(Vector V);

        /// <summary>
        /// Return a human readable form of the matrix
        /// </summary>
        /// 
        /// <returns>The matrix as a string</returns>
        public abstract override String ToString();

        /// <summary>
        /// Compare this matrix with another object.
        /// </summary>
        /// 
        /// <param name="Obj">The object to compare this to</param>
        /// <returns>Returns <c>true</c> if object is equal and has the same values</returns>
        public abstract override bool Equals(Object Obj);

        /// <summary>
        /// Computes the the hash code of this matrix
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public abstract override int GetHashCode();
        #endregion
    }
}
