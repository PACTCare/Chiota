#region Directives
using System;
using System.Collections.Generic;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This abstract class defines a Vector object
    /// </summary>
    internal abstract class Vector : List<object>
    {
        #region Fields
        private int m_length;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the length of this vector
        /// </summary>
        public int Length
        {
            get { return m_length; }
            set { m_length = value; }
        }
        #endregion

        #region Abstract Methods
        /// <summary>
        /// Returns this vector as byte array
        /// </summary>
        /// 
        /// <returns>The encoded vector</returns>
        public abstract byte[] GetEncoded();

        /// <summary>
        /// Return whether this is the zero vector (i.e., all elements are zero)
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if this is the zero vector, <c>false</c> otherwise</returns>
        public abstract bool IsZero();

        /// <summary>
        /// Add another vector to this vector
        /// </summary>
        /// 
        /// <param name="Addend">The other vector</param>
        /// 
        /// <returns>Returns <c>this + Addend</c></returns>
        public abstract Vector Add(Vector Addend);

        /// <summary>
        /// Multiply this vector with a permutation
        /// </summary>
        /// 
        /// <param name="P">The permutation</param>
        /// 
        /// <returns>Returns <c>this*P</c></returns>
        public abstract Vector Multiply(Permutation P);

        /// <summary>
        /// Compare this element with another object
        /// </summary>
        /// 
        /// <param name="Obj">The object for comprison</param>
        /// 
        /// <returns>Returns <c>true</c> if the two objects are equal, <c>false</c> otherwise</returns>
        public abstract override bool Equals(Object Obj);

        /// <summary>
        /// Returns the hash code of this element
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public abstract override int GetHashCode();

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal radix in MSB-first order
        /// </summary>
        /// 
        /// <returns>Returns a String representing this Bitstrings value</returns>
        public abstract override String ToString();
        #endregion
    }
}
