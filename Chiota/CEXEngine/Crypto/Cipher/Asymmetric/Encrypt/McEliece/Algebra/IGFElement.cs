#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This interface defines a finite field element. It is implemented by the classes GFPElement and GF2nElement
    /// </summary>
    internal interface IGFElement
    {
        /// <summary>
        /// Compute the sum of this element and the addend
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        /// 
        /// <returns>Returns <c>this + other</c> (newly created)</returns>
        IGFElement Add(IGFElement Addend);

        /// <summary>
        /// Compute the sum of this element and the addend, overwriting this element
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        void AddToThis(IGFElement Addend);

        /// <summary>
        /// Returns a copy of this GFElement
        /// </summary>
        /// 
        /// <returns>The element copy</returns>
        Object Clone();

        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        bool Equals(Object Obj);

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        int GetHashCode();

        /// <summary>
        /// Compute the multiplicative inverse of this element
        /// </summary>
        /// 
        /// <returns>Returns <c>this<sup>-1</sup></c> (newly created)</returns>
        IGFElement Invert();

        /// <summary>
        /// Checks whether this element is zero
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if <c>this</c> is the zero element</returns>
        bool IsZero();

        /// <summary>
        /// Checks whether this element is one
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if <c>this</c> is the one element</returns>
        bool IsOne();

        /// <summary>
        /// Compute the product of this element and <c>Factor</c>
        /// </summary>
        /// 
        /// <param name="Factor">The factor</param>
        /// 
        /// <returns>Returns <c>this * Factor</c> (newly created)</returns>
        IGFElement Multiply(IGFElement Factor);

        /// <summary>
        /// Compute <c>this * Factor</c> (overwrite <c>this</c>)
        /// </summary>
        /// 
        /// <param name="Factor">The factor</param>
        void MultiplyThisBy(IGFElement Factor);

        /// <summary>
        /// Compute the difference of this element and <c>Minuend</c>
        /// </summary>
        /// 
        /// <param name="Minuend">he minuend</param>
        /// 
        /// <returns>Returns <c>this - Minuend</c> (newly created)</returns>
        IGFElement Subtract(IGFElement Minuend);

        /// <summary>
        /// Compute the difference of this element and <c>minuend</c>, overwriting this element
        /// </summary>
        /// 
        /// <param name="Minuend">The minuend</param>
        void SubtractFromThis(IGFElement Minuend);

        /// <summary>
        /// Returns this element as byte array. The conversion is <a href ="http://grouper.ieee.org/groups/1363/">P1363</a>-conform
        /// </summary>
        /// 
        /// <returns>Returns this element as byte array</returns>
        byte[] ToByteArray();

        /// <summary>
        /// Returns this element as FlexiBigInt. The conversion is <a href="http://grouper.ieee.org/groups/1363/">P1363</a>-conform
        /// </summary>
        /// 
        /// <returns>Returns this element as BigInt</returns>
        BigInteger ToFlexiBigInt();

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal radix in MSB-first order
        /// </summary>
        /// 
        /// <returns>Returns a String representing this Bitstrings value</returns>
        String ToString();

        /// <summary>
        /// Return a String representation of this element. <c>Radix</c> specifies the radix of the String representation
        /// </summary>
        /// 
        /// <param name="Radix">Specifies the radix of the String representation</param>
        /// 
        /// <returns>Returns String representation of this element with the specified radix</returns>
        String ToString(int Radix);
    }
}
