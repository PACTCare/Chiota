#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This abstract class implements an element of the finite field <c>GF(2)^n</c> in either 
    /// <c>optimal normal basis</c> representation (<c>ONB</c>) or in <c>polynomial</c> representation.
    /// </summary>
    internal abstract class GF2nElement : IGFElement
    {
        #region Fields
        // holds a pointer to this element's corresponding field.
        protected GF2nField m_Field;
        // holds the extension degree <c>n</c> of this element's corresponding field.
        protected int m_Degree;
        #endregion

        #region Abstract Methods
        /// <summary>
        /// Compute the sum of this element and <c>Addend</c>.
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        /// 
        /// <returns>Returns <c>this + other</c></returns>
        public abstract IGFElement Add(IGFElement Addend);

        /// <summary>
        /// Compute <c>this + addend</c> (overwrite <c>this</c>)
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        public abstract void AddToThis(IGFElement Addend);

        /// <summary>
        /// Assign the value 0 to this element
        /// </summary>
        public abstract void AssignZero();

        /// <summary>
        /// Assigns the value 1 to this element
        /// </summary>
        public abstract void AssignOne();

        /// <summary>
        /// Return a copy of this GF2nElement
        /// </summary>
        /// 
        /// <returns>The cloned copy</returns>
        public abstract Object Clone();

        /// <summary>
        /// Compute <c>this</c> element + 1
        /// </summary>
        /// 
        /// <returns>Returns <c>this</c> + 1</returns>
        public abstract GF2nElement Increase();

        /// <summary>
        /// Increases this element by one
        /// </summary>
        public abstract void IncreaseThis();

        /// <summary>
        /// Compute the multiplicative inverse of this element
        /// </summary>
        /// 
        /// <returns>Returns <c>this^-1</c> (newly created)</returns>
        public abstract IGFElement Invert();

        /// <summary>
        /// Tests if the GF2nPolynomialElement has 'one' as value
        /// </summary>
        /// 
        /// <returns>Returns true if <c>this</c> equals one (this == 1)</returns>
        public abstract bool IsOne();

        /// <summary>
        /// Checks whether this element is zero
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if <c>this</c> is the zero element</returns>
        public abstract bool IsZero();

        /// <summary>
        /// Compute the product of this element and <c>factor</c>
        /// </summary>
        /// 
        /// <param name="Factor">he factor</param>
        /// 
        /// <returns>Returns <c>this * factor</c> </returns>
        public abstract IGFElement Multiply(IGFElement Factor);

        /// <summary>
        /// Compute <c>this * factor</c> (overwrite <c>this</c>).
        /// </summary>
        /// 
        /// <param name="Factor">The factor</param>
        public abstract void MultiplyThisBy(IGFElement Factor);

        /// <summary>
        /// Solves a quadratic equation.
        /// <para>Let z^2 + z = <c>this</c>. Then this method returns z.</para>
        /// </summary>
        /// 
        /// <returns>Returns z with z^2 + z = <c>this</c></returns>
        public abstract GF2nElement SolveQuadraticEquation();

        /// <summary>
        /// Compute <c>this</c> element to the power of 2
        /// </summary>
        /// 
        /// <returns>Returns <c>this</c>^2</returns>
        public abstract GF2nElement Square();

        /// <summary>
        /// Compute the square root of this element and return the result in a new GF2nElement
        /// </summary>
        /// 
        /// <returns>Returns <c>this^1/2</c> (newly created)</returns>
        public abstract GF2nElement SquareRoot();

        /// <summary>
        /// Compute the square root of this element
        /// </summary>
        public abstract void SquareRootThis();

        /// <summary>
        /// Squares <c>this</c> element
        /// </summary>
        public abstract void SquareThis();

        /// <summary>
        /// Checks whether the indexed bit of the bit representation is set
        /// </summary>
        /// 
        /// <param name="Index">The index of the bit to test</param>
        /// 
        /// <returns>Returns <c>true</c> if the indexed bit is set</returns>
        public abstract bool TestBit(int Index);

        /// <summary>
        /// Returns whether the rightmost bit of the bit representation is set. 
        /// This is needed for data conversion according to 1363.
        /// </summary>
        /// 
        /// <returns>Returns true if the rightmost bit of this element is set</returns>
        public abstract bool TestRightmostBit();

        /// <summary>
        /// Converts this GF2nPolynomialElement to an integer according to 1363
        /// </summary>
        /// 
        /// <returns>Returns a BigInteger representing the value of this GF2nPolynomialElement</returns>
        public abstract BigInteger ToFlexiBigInt();

        /// <summary>
        /// Converts this GF2nPolynomialElement to a byte[] according to 1363
        /// </summary>
        /// 
        /// <returns>Returns a byte[] representing the value of this GF2nPolynomialElement</returns>
        public abstract byte[] ToByteArray();

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal or binary radix in MSB-first order
        /// </summary>
        /// 
        /// <param name="Radix">The radix to use (2 or 16, otherwise 2 is used)</param>
        /// 
        /// <returns>Returns a String representing this Bitstrings value.</returns>
        public abstract String ToString(int Radix);

        /// <summary>
        /// Computes the trace of this element
        /// </summary>
        /// 
        /// <returns>Returns the trace of this element</returns>
        public abstract int Trace();
        #endregion

        #region Public Methods
        /// <summary>
        /// Performs a basis transformation of this element to the given GF2nField <c>basis</c>
        /// </summary>
        /// 
        /// <param name="Basis">The GF2nField representation to transform this element to</param>
        /// 
        /// <returns>Returns this element in the representation of <c>basis</c></returns>
        public GF2nElement Convert(GF2nField Basis)
        {
            return m_Field.Convert(this, Basis);
        }

        /// <summary>
        /// Returns the field of this element
        /// </summary>
        /// 
        /// <returns>The field of this element</returns>
        public GF2nField GetField()
        {
            return m_Field;
        }

        /// <summary>
        /// Compute the difference of this element and <c>minuend</c>
        /// </summary>
        /// 
        /// <param name="Minuend">The minuend</param>
        /// 
        /// <returns>Returns <c>this - minuend</c> (newly created)</returns>
        public IGFElement Subtract(IGFElement Minuend)
        {
            return Add(Minuend);
        }

        /// <summary>
        /// Compute the difference of this element and <c>minuend</c>,  overwriting this element
        /// </summary>
        /// 
        /// <param name="Minuend">The minuend</param>
        public void SubtractFromThis(IGFElement Minuend)
        {
            AddToThis(Minuend);
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
        public override abstract bool Equals(Object Obj);

        /// <summary>
        /// Returns the hash code of this element
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override abstract int GetHashCode();

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal radix in MSB-first order
        /// </summary>
        /// 
        /// <returns>Returns a String representing this Bitstrings value</returns>
        public override abstract String ToString();
        #endregion
    }
}
