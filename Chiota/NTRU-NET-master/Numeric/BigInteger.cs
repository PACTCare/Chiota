#region Directives
using System;
using System.Runtime.Serialization;
using VTDev.Libraries.CEXEngine.Crypto.Prng ;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Code Base Guides:
// Based on the Deveel Math library by Antonello Provenzano: <see href="https://github.com/deveel/deveel-math/tree/master/src/Deveel.Math/Deveel.Math">BigInteger class, 
// and Open JDK <see href="http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8-b132/java/math/BigInteger.java#BigInteger">BigInteger.java</see>.
// 
// Implementation Details:
// An implementation of a BigInteger class. 
// Written by John Underhill, March 29, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// <h3>This class represents immutable integer numbers of arbitrary length</h3>
    /// 
    /// <description>Immutable arbitrary-precision integers.</description>
    /// <para>All operations behave as if BigIntegers were represented in two's-complement notation.  
    /// BigInteger provides operations for modular arithmetic, GCD calculation, primality testing, prime generation, bit manipulation, and a few other miscellaneous operations.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Creating a random prime example:</description>
    /// <code>
    /// BigInteger p = BigInteger.ProbablePrime(BitLength, new SecureRandom());
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.2.0">Updated and expanded the implementation</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <para>Semantics of arithmetic operations exactly mimic those of Java's integer arithmetic operators, as defined in The Java Language Specification.
    /// For example, division by zero throws an ArithmeticException, and division of a negative by a positive yields a negative (or zero) remainder.
    /// All of the details in the Spec concerning overflow are ignored, as BigIntegers are made as large as necessary to accommodate the results of an operation.</para>
    /// 
    /// <para>Semantics of shift operations allow for negative shift distances.  
    /// A right-shift with a negative shift distance results in a left shift, and vice-versa.</para>
    /// 
    /// <para>The binary operators (<c>And</c>, <c>Or</c>, <c>Xor</c>) implicitly perform sign extension on the shorter of the two operands prior to performing the operation.</para>
    /// 
    /// <para>Modular arithmetic operations are provided to compute residues, perform exponentiation, and compute multiplicative inverses.  
    /// These methods always return a non-negative result, between <c>0</c> and <c>(Modulus - 1)</c>, inclusive.</para>
    /// 
    /// <para>Bit operations operate on a single bit of the two's-complement representation of their operand.  
    /// If necessary, the operand is sign-extended so that it contains the designated bit.  
    /// None of the single-bit operations can produce a BigInteger with a different sign from the BigInteger being operated on, as they affect only a single bit, 
    /// and the "infinite word size" abstraction provided by this class ensures that there are infinitely many "virtual sign bits" preceding each BigInteger.</para>
    /// <para>Large numbers are typically used in security applications and therefore BigIntegers offer dedicated functionality like the generation of large 
    /// prime numbers or the computation of modular inverse.</para>
    /// <para>Since the class was modeled to offer all the functionality as the Integer class does, it provides even methods that operate bitwise 
    /// on a two's complement representation of large integers. 
    /// Note however that the implementations favors an internal representation where magnitude and sign are treated separately. 
    /// Hence such operations are inefficient and should be discouraged. 
    /// In simple words: Do NOT implement any bit fields based on BigInteger.</para>
    /// </remarks>
    [Serializable]
    public class BigInteger : IComparable<BigInteger>, IConvertible, ISerializable
    {
        #region Public Fields
        /// <summary>
        /// The BigInteger constant 0
        /// </summary>
        public static readonly BigInteger Zero = new BigInteger(0, 0);

        /// <summary>
        /// The BigInteger constant 1
        /// </summary>
        public static readonly BigInteger One = new BigInteger(1, 1);

        /// <summary>
        /// The BigInteger constant 10
        /// </summary>
        public static readonly BigInteger Ten = new BigInteger(1, 10);
        #endregion

        #region Private Fields
        private static readonly SecureRandom _randomSource = new SecureRandom();
        // The magnitude of this big integer. This array holds unsigned little endian digits.
        [NonSerialized]
        internal int[] _digits;
        // The length of this in measured in ints. Can be less than Digits.Length().
        [NonSerialized]
        internal int _numberLength;
        // The sign of this
        [NonSerialized]
        internal int _sign;
        // The BigInteger constant -1
        internal static readonly BigInteger MinusOne = new BigInteger(-1, 1);
        // The BigInteger constant 0 used for comparison
        internal static readonly int EQUALS = 0;
        // The BigInteger constant 1 used for comparison
        internal static readonly int GREATER = 1;
        // The BigInteger constant -1 used for comparison
        internal static readonly int LESS = -1;

        // All the BigInteger numbers in the range [0,10] are cached.
        private static readonly BigInteger[] _smallValues = 
        {
            Zero, One, new BigInteger(1, 2), new BigInteger(1, 3), new BigInteger(1, 4), new BigInteger(1, 5),
            new BigInteger(1, 6), new BigInteger(1, 7), new BigInteger(1, 8), new BigInteger(1, 9), Ten 
        };

        private static readonly BigInteger[] _twoPows;
        [NonSerialized]
        private int _firstNonzeroDigit = -2;
        // Cache for the hash code
        [NonSerialized]
        private int _hashCode = 0;
        #endregion

        #region Properties
        /// <summary>
        /// Returns the number of bits in the binary representation of this which differ from the sign bit. 
        /// <para>Use BitLength(0) if you want to know the length of the binary value in bits.
        /// If this is positive the result is equivalent to the number of bits set in the binary representation of this.
        /// If this is negative the result is equivalent to the number of bits set in the binary representation of -this - 1.</para>
        /// </summary>
        public int BitCount
        {
            get { return BitLevel.BitCount(this); }
        }

        /// <summary>
        /// Returns the length of the value's two's complement representation without 
        /// leading zeros for positive numbers / without leading ones for negative values.
        /// <para>The two's complement representation of this will be at least BitLength() + 1 bits long.
        /// The value will fit into an int if <c>bitLength() &lt; 32</c> or into a long if <c>bitLength() &lt; 64</c>.</para>
        /// </summary>
        public int BitLength
        {
            get { return BitLevel.BitLength(this); }
        }

        /// <summary>
        /// Returns the position of the lowest set bit in the two's complement representation of this BigInteger.
        /// <para>If all bits are zero (this=0) then -1 is returned as result.</para>
        /// </summary>
        public int LowestSetBit
        {
            get
            {
                if (_sign == 0)
                    return -1;

                // (sign != 0) implies that exists some non zero digit
                int i = FirstNonzeroDigit;
                return ((i << 5) + IntUtils.NumberOfTrailingZeros(_digits[i]));
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Static constructor
        /// </summary>
        static BigInteger()
        {
            _twoPows = new BigInteger[32];

            for (int i = 0; i < _twoPows.Length; i++)
                _twoPows[i] = BigInteger.ValueOf(1L << i);
        }

        /// <summary>
        /// Constructs a new BigInteger from the given two's complement representation.
        /// <para>The most significant byte is the entry at index 0.
        /// The most significant bit of this entry determines the sign of the new BigInteger instance.
        /// The given array must not be empty.</para>
        /// </summary>
        /// 
        /// <param name="Value">Two's complement representation of the new BigInteger</param>
        public BigInteger(byte[] Value)
        {
            if (Value.Length == 0)
                throw new FormatException("Zero length BigInteger");

            if (Value[0] > sbyte.MaxValue)
            {
                _sign = -1;
                PutBytesNegativeToIntegers(Value);
            }
            else
            {
                _sign = 1;
                PutBytesPositiveToIntegers(Value);
            }
            CutOffLeadingZeroes();
        }

        /// <summary>
        /// Constructs a new BigInteger instance with the given sign and the given magnitude.
        /// <para>The sign is given as an integer (-1 for negative, 0 for zero, 1 for positive).
        /// The magnitude is specified as a byte array. The most significant byte is the entry at index 0.</para>
        /// </summary>
        /// 
        /// <param name="Signum">Sign of the new BigInteger (-1 for negative, 0 for zero, 1 for positive)</param>
        /// <param name="Magnitude">Magnitude of the new BigInteger with the most significant byte first</param>
        /// 
        /// <exception cref="FormatException">Thrown if an invalid Signum or Magnitude is passed</exception>
        public BigInteger(int Signum, byte[] Magnitude)
        {
            if (Magnitude == null)
                throw new NullReferenceException();
            if ((Signum < -1) || (Signum > 1))
                throw new FormatException("Invalid signum value!");
            if (Signum == 0)
            {
                foreach (byte element in Magnitude)
                {
                    if (element != 0)
                        throw new FormatException("signum-magnitude mismatch!");
                }
            }

            if (Magnitude.Length == 0)
            {
                _sign = 0;
                _numberLength = 1;
                _digits = new int[] { 0 };
            }
            else
            {
                _sign = Signum;
                PutBytesPositiveToIntegers(Magnitude);
                CutOffLeadingZeroes();
            }
        }

        /// <summary>
        /// Constructs a random non-negative BigInteger instance in the range [0, 2^(numBits)-1]
        /// </summary>
        /// 
        /// <param name="NumBits">Maximum length of the new BigInteger in bits</param>
        /// <param name="Rnd">An optional random generator to be used</param>
        /// 
        /// <exception cref="ArgumentException">Thrown  if NumBits &gt; 0</exception>
        public BigInteger(int NumBits, SecureRandom Rnd)
        {
            if (NumBits < 0)
                throw new ArgumentException("numBits must be non-negative");

            if (NumBits == 0)
            {
                _sign = 0;
                _numberLength = 1;
                _digits = new int[] { 0 };
            }
            else
            {
                _sign = 1;
                _numberLength = (int)(uint)(NumBits + 31) >> 5;
                _digits = new int[_numberLength];

                for (int i = 0; i < _numberLength; i++)
                    _digits[i] = Rnd.Next();

                // Using only the necessary bits
                _digits[_numberLength - 1] = IntUtils.URShift(_digits[_numberLength - 1], (-NumBits) & 31);
                CutOffLeadingZeroes();
            }
        }

        /// <summary>
        /// Constructs a random BigInteger instance in the range [0, 2^(bitLength)-1] which is probably prime. 
        /// <para>The probability that the returned BigInteger is prime is beyond (1-1/2^certainty).</para>
        /// </summary>
        /// 
        /// <param name="BitLength">Length of the new BigInteger in bits</param>
        /// <param name="Certainty">Tolerated primality uncertainty</param>
        /// <param name="Rnd">An optional random generator to be used</param>
        public BigInteger(int BitLength, int Certainty, SecureRandom Rnd)
        {
            if (BitLength < 2)
                throw new ArithmeticException("bitLength < 2");

            BigInteger me = Primality.ConsBigInteger(BitLength, Certainty, Rnd);
            _sign = me._sign;
            _numberLength = me._numberLength;
            _digits = me._digits;
        }

        /// <summary>
        /// Constructs a new BigInteger instance from the string representation. 
        /// <para>The string representation consists of an optional minus sign 
        /// followed by a non-empty sequence of decimal digits.</para>
        /// </summary>
        /// 
        /// <param name="Value">String representation of the new BigInteger</param>
        public BigInteger(String Value)
            : this(Value, 10)
        {
        }

        /// <summary>
        /// Constructs a new BigInteger instance from the string representation.
        /// <para>The string representation consists of an optional minus sign 
        /// followed by a non-empty sequence of digits in the specified radix.
        /// For the conversion the method CharHelper.Digit(char, radix) is used.</para>
        /// </summary>
        /// 
        /// <param name="Value">String representation of the new BigInteger</param>
        /// <param name="Radix">The base to be used for the conversion</param>
        public BigInteger(String Value, int Radix)
        {
            if (Value == null)
                throw new NullReferenceException();
            if ((Radix < CharUtils.MIN_RADIX) || (Radix > CharUtils.MAX_RADIX))
                throw new FormatException("Radix out of range");
            if (Value.Length == 0)
                throw new FormatException("Zero length BigInteger");

            SetFromString(this, Value, Radix);
        }

        /// <summary>
        /// Creates a new BigInteger with the given sign and magnitude.
        /// <para>This constructor does not create a copy, so any changes to the reference will affect the new number.</para>
        /// </summary>
        /// 
        /// <param name="Signum">The sign of the number represented by digits</param>
        /// <param name="Digits">The magnitude of the number</param>
        internal BigInteger(int Signum, int[] Digits)
        {
            if (Digits.Length == 0)
            {
                _sign = 0;
                _numberLength = 1;
                this._digits = new int[] { 0 };
            }
            else
            {
                _sign = Signum;
                _numberLength = Digits.Length;
                this._digits = Digits;
                CutOffLeadingZeroes();
            }
        }

        /// <summary>
        /// Constructs a number which array is of size 1
        /// </summary>
        /// 
        /// <param name="Sign">The sign of the number</param>
        /// <param name="Value">The only one digit of array</param>
        internal BigInteger(int Sign, int Value)
        {
            this._sign = Sign;
            _numberLength = 1;
            _digits = new int[] { Value };
        }

        /// <summary>
        /// Creates a new BigInteger whose value is equal to the specified long
        /// </summary>
        /// 
        /// <param name="Sign">The sign of the number</param>
        /// <param name="Value">The value of the new BigInteger</param>
        internal BigInteger(int Sign, long Value)
        {
            // PRE: (val >= 0) && (sign >= -1) && (sign <= 1)
            this._sign = Sign;
            if (((ulong)Value & 0xFFFFFFFF00000000L) == 0)
            {
                // It fits in one 'int'
                _numberLength = 1;
                _digits = new int[] { (int)Value };
            }
            else
            {
                _numberLength = 2;
                _digits = new int[] { (int)Value, (int)(Value >> 32) };
            }
        }

        /// <summary>
        /// Constructs a number without to create new space.
        /// <para>This construct should be used only if the three fields of representation are known.</para>
        /// </summary>
        /// 
        /// <param name="Sign">The sign of the number</param>
        /// <param name="NumberLength">The length of the internal array</param>
        /// <param name="Digits">A reference of some array created before</param>
        internal BigInteger(int Sign, int NumberLength, int[] Digits)
        {
            this._sign = Sign;
            this._numberLength = NumberLength;
            this._digits = Digits;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns a (new) BigInteger whose value is the absolute value of this
        /// </summary>
        /// 
        /// <returns><c>Abs(this)</c></returns>
        public BigInteger Abs()
        {
            return ((_sign < 0) ? new BigInteger(1, _numberLength, _digits) : this);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this + val</c>
        /// </summary>
        /// 
        /// <param name="Augend">Value to be added to this</param>
        /// 
        /// <returns><c>this + val</c></returns>
        public BigInteger Add(BigInteger Augend)
        {
            return Elementary.Add(this, Augend);
        }

        /// <summary>
        /// Computes the bit per bit operator between this number and the given one
        /// </summary>
        /// 
        /// <param name="Value">The value to be and'ed with the current.</param>
        /// 
        /// <returns>
        /// Returns a new BigInteger whose value is <c>this &amp; Value</c>.
        /// </returns>
        public BigInteger And(BigInteger Value)
        {
            return Logical.And(this, Value);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this &amp; ~Value</c>.
        /// <para>Evaluating <c>x.AndNot(Value)</c> returns the same result as <c>x.And(Value.Not())</c>.</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be not'ed and then and'ed with this</param>
        /// 
        /// <returns><c>this &amp; ~Value</c></returns>
        public BigInteger AndNot(BigInteger Value)
        {
            return Logical.AndNot(this, Value);
        }

        /// <summary>
        /// Returns a new BigInteger which has the same binary representation as this but with the bit at position N cleared.
        /// <para>The result is equivalent to this <c>&amp; ~(2^n)</c>.
        /// </para>
        /// </summary>
        /// 
        /// <param name="N">Position where the bit in this has to be cleared</param>
        /// 
        /// <returns><c>this &amp; ~(2^n)</c></returns>
        public BigInteger ClearBit(int N)
        {
            if (TestBit(N))
                return BitLevel.FlipBit(this, N);

            return this;
        }

        /// <summary>
        /// Compares this BigInteger with Value.
        /// <para>Returns one of the three values 1, 0, or -1.</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be compared with this</param>
        /// 
        /// <returns>Returns 1 if this > Value, -1 if this &lt; Value, 0 if this == Value</returns>
        public int CompareTo(BigInteger Value)
        {
            if (_sign > Value._sign)
                return GREATER;
            if (_sign < Value._sign)
                return LESS;
            if (_numberLength > Value._numberLength)
                return _sign;
            if (_numberLength < Value._numberLength)
                return -Value._sign;

            // Equal sign and equal numberLength
            return (_sign * Elementary.CompareArrays(_digits, Value._digits, _numberLength));
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this / Divisor</c>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns><c>this / Divisor</c></returns>
        public BigInteger Divide(BigInteger Divisor)
        {
            if (Divisor._sign == 0)
                throw new ArithmeticException("BigInteger divide by zero");

            int divisorSign = Divisor._sign;
            if (Divisor.IsOne())
                return ((Divisor._sign > 0) ? this : this.Negate());

            int thisSign = _sign;
            int thisLen = _numberLength;
            int divisorLen = Divisor._numberLength;

            if (thisLen + divisorLen == 2)
            {
                long val = (_digits[0] & 0xFFFFFFFFL) / (Divisor._digits[0] & 0xFFFFFFFFL);
                if (thisSign != divisorSign)
                    val = -val;

                return ValueOf(val);
            }

            int cmp = ((thisLen != divisorLen) ? ((thisLen > divisorLen) ? 1 : -1) : Elementary.CompareArrays(_digits, Divisor._digits, thisLen));
            if (cmp == EQUALS)
                return ((thisSign == divisorSign) ? One : MinusOne);

            if (cmp == LESS)
                return Zero;

            int resLength = thisLen - divisorLen + 1;
            int[] resDigits = new int[resLength];
            int resSign = ((thisSign == divisorSign) ? 1 : -1);

            if (divisorLen == 1)
                Division.DivideArrayByInt(resDigits, _digits, thisLen, Divisor._digits[0]);
            else
                Division.Divide(resDigits, resLength, _digits, thisLen, Divisor._digits, divisorLen);

            BigInteger result = new BigInteger(resSign, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Returns a BigInteger array which contains <c>this / Divisor</c> at index 0 and <c>this % Divisor</c> at index 1
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns><c>[this / Divisor, this % Divisor]</c></returns>
        public BigInteger[] DivideAndRemainder(BigInteger Divisor)
        {
            int divisorSign = Divisor._sign;
            if (divisorSign == 0)
                throw new ArithmeticException("BigInteger divide by zero");

            int divisorLen = Divisor._numberLength;
            int[] divisorDigits = Divisor._digits;

            if (divisorLen == 1)
                return Division.DivideAndRemainderByInteger(this, divisorDigits[0], divisorSign);

            // res[0] is a quotient and res[1] is a remainder:
            int[] thisDigits = _digits;
            int thisLen = _numberLength;
            int cmp = (thisLen != divisorLen) ? ((thisLen > divisorLen) ? 1 : -1) : Elementary.CompareArrays(thisDigits, divisorDigits, thisLen);
            if (cmp < 0)
                return new BigInteger[] { Zero, this };

            int thisSign = _sign;
            int quotientLength = thisLen - divisorLen + 1;
            int remainderLength = divisorLen;
            int quotientSign = ((thisSign == divisorSign) ? 1 : -1);
            int[] quotientDigits = new int[quotientLength];
            int[] remainderDigits = Division.Divide(quotientDigits, quotientLength, thisDigits, thisLen, divisorDigits, divisorLen);

            BigInteger result0 = new BigInteger(quotientSign, quotientLength, quotientDigits);
            BigInteger result1 = new BigInteger(thisSign, remainderLength, remainderDigits);
            result0.CutOffLeadingZeroes();
            result1.CutOffLeadingZeroes();

            return new BigInteger[] { result0, result1 };
        }

        /// <summary>
        /// Returns a new BigInteger which has the same binary representation as this but with the bit at position N flipped. 
        /// <para>The result is equivalent to this ^ 2^N.</para>
        /// </summary>
        /// 
        /// <param name="N">Position where the bit in this has to be flipped</param>
        /// 
        /// <returns>Returns <c>this ^ 2^N</c></returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if a negative bit address is used</exception>
        public BigInteger FlipBit(int N)
        {
            if (N < 0)
                throw new ArithmeticException("Negative bit address!");

            return BitLevel.FlipBit(this, N);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is greatest common divisor of this and Value.
        /// <para>If this==0 and Value==0 then zero is returned, otherwise the result is positive.</para>
        /// </summary>
        /// 
        /// <param name="Value">Value with which the greatest common divisor is computed.</param>
        /// <returns><c>Gcd(this, Value)</c></returns>
        public BigInteger Gcd(BigInteger Value)
        {
            BigInteger val1 = this.Abs();
            BigInteger val2 = Value.Abs();

            // To avoid a possible division by zero
            if (val1.Signum() == 0)
                return val2;
            else if (val2.Signum() == 0)
                return val1;

            // Optimization for small operands
            // (op2.bitLength() < 64) and (op1.bitLength() < 64)
            if (((val1._numberLength == 1) || ((val1._numberLength == 2) && (val1._digits[1] > 0))) && (val2._numberLength == 1 || (val2._numberLength == 2 && val2._digits[1] > 0)))
                return BigInteger.ValueOf(Division.GcdBinary(val1.ToInt64(), val2.ToInt64()));

            return Division.GcdBinary(val1.Copy(), val2.Copy());
        }

        /// <summary>
        /// Tests whether this BigInteger is probably prime.
        /// <para>If true is returned, then this is prime with a probability beyond <c>(1-1/2^certainty)</c>.
        /// If false is returned, then this is definitely composite.
        /// If the argument Certainty &lt;= 0, then this method returns true.</para>
        /// </summary>
        /// 
        /// <param name="Certainty">Tolerated primality uncertainty</param>
        /// 
        /// <returns>Returns true, if this is probably prime, false  otherwise</returns>
        public bool IsProbablePrime(int Certainty)
        {
            return Primality.IsProbablePrime(Abs(), Certainty);
        }

        /// <summary>
        /// Returns the maximum of this BigInteger and Value
        /// </summary>
        /// 
        /// <param name="Value">Value to be used to compute the maximum with this</param>
        /// 
        /// <returns>Max(this, Value)</returns>
        public BigInteger Max(BigInteger Value)
        {
            return ((this.CompareTo(Value) == GREATER) ? this : Value);
        }

        /// <summary>
        /// Returns the minimum of this BigInteger and Value
        /// </summary>
        /// 
        /// <param name="Value">Value to be used to compute the minimum with this</param>
        /// 
        /// <returns><c>Min(this, Value)</c></returns>
        public BigInteger Min(BigInteger Value)
        {
            return ((this.CompareTo(Value) == LESS) ? this : Value);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this Mod M</c>.
        /// <para>The modulus M must be positive.
        /// The result is guaranteed to be in the interval (0, M) (0 inclusive, m exclusive).
        /// The behavior of this function is not equivalent to the behavior of the % operator defined for the built-in int's.</para>
        /// </summary>
        /// 
        /// <param name="M">The modulus</param>
        /// 
        /// <returns>Returns <c>this Mod M</c></returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if M == null or M &lt; 0</exception>
        public BigInteger Mod(BigInteger M)
        {
            if (M._sign <= 0)
                throw new ArithmeticException("BigInteger: modulus not positive!");

            BigInteger rem = Remainder(M);

            return ((rem._sign < 0) ? rem.Add(M) : rem);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this^Exponent Mod M</c>.
        /// <para>The modulus M must be positive.
        /// The result is guaranteed to be in the interval (0, M) (0 inclusive, m exclusive).
        /// If the Exponent is negative, then <c>this.ModInverse(M)^(-Exponent) Mod M)</c> is computed.
        /// The inverse of this only exists if this is relatively prime to M, otherwise an exception is thrown.</para>
        /// </summary>
        /// 
        /// <param name="Exponent">The exponent</param>
        /// <param name="M">The modulus</param>
        /// 
        /// <returns><c>this^Exponent Mod M</c></returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if M &lt; 0 or if Exponent&lt;0 and this is not relatively prime to M</exception>
        public BigInteger ModPow(BigInteger Exponent, BigInteger M)
        {
            if (M._sign <= 0)
                throw new ArithmeticException("BigInteger: modulus not positive");

            BigInteger b = this;

            if (M.IsOne() | (Exponent._sign > 0 & b._sign == 0))
                return BigInteger.Zero;

            if (b._sign == 0 && Exponent._sign == 0)
                return BigInteger.One;

            if (Exponent._sign < 0)
            {
                b = ModInverse(M);
                Exponent = Exponent.Negate();
            }
            // From now on: (m > 0) and (exponent >= 0)
            BigInteger res = (M.TestBit(0)) ? Division.OddModPow(b.Abs(), Exponent, M) : Division.EvenModPow(b.Abs(), Exponent, M);

            // -b^e mod m == ((-1 mod m) * (b^e mod m)) mod m
            if ((b._sign < 0) && Exponent.TestBit(0))
                res = M.Subtract(BigInteger.One).Multiply(res).Mod(M);

            // else exponent is even, so base^exp is positive
            return res;
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>1/this Mod M</c>. 
        /// <para>The modulus M must be positive.
        /// The result is guaranteed to be in the interval (0, M) (0 inclusive, M exclusive).
        /// If this is not relatively prime to M, then an exception is thrown.</para>
        /// </summary>
        /// 
        /// <param name="M">The modulus</param>
        /// 
        /// <returns>Returns <c>1/this Mod M</c></returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if M &lt; 0 or, if this is not relatively prime to code M</exception>
        public BigInteger ModInverse(BigInteger M)
        {
            if (M._sign <= 0)
                throw new ArithmeticException("modulus not positive!");

            // If both are even, no inverse exists
            if (!(TestBit(0) || M.TestBit(0)))
                throw new ArithmeticException("BigInteger not invertible!");

            if (M.IsOne())
                return Zero;


            // From now on: (m > 1)
            BigInteger res = Division.ModInverseMontgomery(Abs().Mod(M), M);
            if (res._sign == 0)
                throw new ArithmeticException("BigInteger not invertible!");

            res = ((_sign < 0) ? M.Subtract(res) : res);

            return res;

        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this * Value</c>
        /// </summary>
        /// 
        /// <param name="Multiplicand">Value to be multiplied with this</param>
        /// <returns>Returns <c>this * Value</c></returns>
        public BigInteger Multiply(BigInteger Multiplicand)
        {
            // This let us to throw NullPointerException when val == null
            if (Multiplicand._sign == 0)
                return Zero;
            if (_sign == 0)
                return Zero;

            return Multiplication.Multiply(this, Multiplicand);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is the <c>-this</c>
        /// </summary>
        /// 
        /// <returns><c>-this</c></returns>
        public BigInteger Negate()
        {
            return ((_sign == 0) ? this : new BigInteger(-_sign, _numberLength, _digits));
        }

        /// <summary>
        /// Returns the smallest integer x > this which is probably prime as a BigInteger instance.
        /// <para>The probability that the returned BigInteger is prime is beyond (1-1/2^80).</para>
        /// </summary>
        /// 
        /// <returns>Smallest integer > this which is robably prime</returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if this &lt; 0</exception>
        public BigInteger NextProbablePrime()
        {
            if (_sign < 0)
                throw new ArithmeticException("start < 0");

            return Primality.NextProbablePrime(this);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>~this</c>.
        /// <para>The result of this operation is <c>-this-1</c>.</para>
        /// </summary>
        /// 
        /// <returns>Returns <c>~this</c></returns>
        public BigInteger Not()
        {
            return Logical.Not(this);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this | Value</c>
        /// </summary>
        /// 
        /// <param name="Value">Value to be Or'ed with this</param>
        /// 
        /// <returns>Returns <c>this | Value</c></returns>
        public BigInteger Or(BigInteger Value)
        {
            return Logical.Or(this, Value);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this ^ Exponent</c>
        /// </summary>
        /// 
        /// <param name="Exponent">Exponent to which this is raised</param>
        /// 
        /// <returns>Returns <c>this ^ Exponent</c></returns>
        public BigInteger Pow(int Exponent)
        {
            if (Exponent < 0)
                throw new ArithmeticException("Negative exponent");

            if (Exponent == 0)
                return One;
            else if (Exponent == 1 || Equals(One) || Equals(Zero))
                return this;

            // if even take out 2^x factor which we can calculate by shifting.
            if (!TestBit(0))
            {
                int x = 1;
                while (!TestBit(x))
                    x++;

                return GetPowerOfTwo(x * Exponent).Multiply(this.ShiftRight(x).Pow(Exponent));
            }

            return Multiplication.Pow(this, Exponent);
        }

        /// <summary>
        /// Returns a random positive BigInteger instance in the range <c>[0, 2^(bitLength)-1]</c> which is probably prime.
        /// <para>The probability that the returned BigInteger is prime is beyond (1-1/2^80).</para>
        /// </summary>
        /// 
        /// <param name="BitLength">Length of the new BigInteger in bits</param>
        /// <param name="Rnd">Random generator used to generate the new BigInteger</param>
        /// 
        /// <returns>Returns probably prime random BigInteger instance</returns>
        public static BigInteger ProbablePrime(int BitLength, SecureRandom Rnd)
        {
            return new BigInteger(BitLength, 100, Rnd);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this % Divisor</c>.
        /// <para>Regarding signs this methods has the same behavior as the % operator on int's, 
        /// i.e. the sign of the remainder is the same as the sign of this.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns>Returns <c>this % Divisor</c></returns>
        public BigInteger Remainder(BigInteger Divisor)
        {
            if (Divisor._sign == 0)
                throw new ArithmeticException("BigInteger divide by zero!");

            int thisLen = _numberLength;
            int divisorLen = Divisor._numberLength;
            if (((thisLen != divisorLen) ? ((thisLen > divisorLen) ? 1 : -1) : Elementary.CompareArrays(_digits, Divisor._digits, thisLen)) == LESS)
                return this;

            int resLength = divisorLen;
            int[] resDigits = new int[resLength];
            if (resLength == 1)
            {
                resDigits[0] = Division.RemainderArrayByInt(_digits, thisLen, Divisor._digits[0]);
            }
            else
            {
                int qLen = thisLen - divisorLen + 1;
                resDigits = Division.Divide(null, qLen, _digits, thisLen, Divisor._digits, divisorLen);
            }

            BigInteger result = new BigInteger(_sign, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Returns a new BigInteger which has the same binary representation as this but with the bit at position N set.
        /// <para>The result is equivalent to <c>this | 2^n</c>.</para>
        /// </summary>
        /// 
        /// <param name="N">Position where the bit in this has to be set</param>
        /// 
        /// <returns>Returns <c>this | 2^n</c></returns>
        public BigInteger SetBit(int N)
        {
            if (!TestBit(N))
                return BitLevel.FlipBit(this, N);

            return this;
        }

        /// <summary>
        /// Returns a new BigInteger whose value is this &lt;&lt; N.
        /// <para>The result is equivalent to <c>this * 2^n</c> if n >= 0.
        /// The shift distance may be negative which means that this is shifted right.
        /// The result then corresponds to <c>Floor(this / 2^(-n))</c>.</para>
        /// </summary>
        /// 
        /// <param name="N">The shift distance in bits</param>
        /// 
        /// <returns>Returns <c>this &lt;&lt; N</c> if n >= 0, <c>this >> (-N)</c> otherwise</returns>
        public BigInteger ShiftLeft(int N)
        {
            if ((N == 0) || (_sign == 0))
                return this;

            return ((N > 0) ? BitLevel.ShiftLeft(this, N) : BitLevel.ShiftRight(this, -N));
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this >> N</c>.
        /// <para>For negative arguments, the result is also negative. 
        /// The shift distance may be negative which means that this is shifted left.</para>
        /// </summary>
        /// 
        /// <param name="N">The shift distance in bits</param>
        /// 
        /// <returns>this >> N, if N >= 0; this &lt;&lt; (-n) otherwise</returns>
        public BigInteger ShiftRight(int N)
        {
            if ((N == 0) || (_sign == 0))
                return this;

            return ((N > 0) ? BitLevel.ShiftRight(this, N) : BitLevel.ShiftLeft(this, -N));
        }

        /// <summary>
        /// Returns the sign of this BigInteger
        /// </summary>
        /// 
        /// <returns>Returns -1 if this &lt; 0, 0 if this == 0, 1 if this > 0</returns>
        public int Signum()
        {
            return _sign;
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this - val</c>
        /// </summary>
        /// 
        /// <param name="Subtrahend">Value to be subtracted from this</param>
        /// 
        /// <returns><c>this - val</c></returns>
        public BigInteger Subtract(BigInteger Subtrahend)
        {
            return Elementary.Subtract(this, Subtrahend);
        }

        /// <summary>
        /// Tests whether the bit at position N in this is set.
        /// <para>The result is equivalent to <c>this &amp; (2^n) != 0</c>.</para>
        /// </summary>
        /// 
        /// <param name="N">Position where the bit in this has to be inspected.</param>
        /// 
        /// <returns>Returns this &amp; (2^n) != 0</returns>
        /// 
        /// <remarks>
        /// Implementation Note: Usage of this method is not 
        /// recommended as the current implementation is not efficient.
        /// </remarks>
        /// 
        /// <exception cref="ArithmeticException">Thrown if a negative bit address is used</exception>
        public bool TestBit(int N)
        {
            if (N == 0)
                return ((_digits[0] & 1) != 0);
            if (N < 0)
                throw new ArithmeticException("Negative bit address!");

            int intCount = (int)(uint)N >> 5;
            if (intCount >= _numberLength)
                return (_sign < 0);

            int digit = _digits[intCount];
            N = (1 << (N & 31)); // int with 1 set to the needed position

            if (_sign < 0)
            {
                int firstNonZeroDigit = FirstNonzeroDigit;
                if (intCount < firstNonZeroDigit)
                    return false;
                else if (firstNonZeroDigit == intCount)
                    digit = -digit;
                else
                    digit = ~digit;
            }

            return ((digit & N) != 0);
        }

        /// <summary>
        /// Returns the two's complement representation of this BigInteger in a byte array
        /// </summary>
        /// 
        /// <returns>Two's complement representation of this</returns>
        public byte[] ToByteArray()
        {
            if (_sign == 0)
                return new byte[] { 0 };

            BigInteger temp = this;
            int bitLen = BitLength;
            int iThis = FirstNonzeroDigit;
            int bytesLen = ((int)(uint)bitLen >> 3) + 1;
            // Puts the little-endian int array representing the magnitude of this BigInteger into the big-endian byte array.
            byte[] bytes = new byte[bytesLen];
            int firstByteNumber = 0;
            int highBytes;
            int digitIndex = 0;
            int bytesInInteger = 4;
            int digit;
            int hB;

            if (bytesLen - (_numberLength << 2) == 1)
            {
                bytes[0] = (byte)((_sign < 0) ? -1 : 0);
                highBytes = 4;
                firstByteNumber++;
            }
            else
            {
                hB = bytesLen & 3;
                highBytes = (hB == 0) ? 4 : hB;
            }

            digitIndex = iThis;
            bytesLen -= iThis << 2;

            if (_sign < 0)
            {
                digit = -temp._digits[digitIndex];
                digitIndex++;
                if (digitIndex == _numberLength)
                    bytesInInteger = highBytes;

                for (int i = 0; i < bytesInInteger; i++, digit >>= 8)
                    bytes[--bytesLen] = (byte)digit;

                while (bytesLen > firstByteNumber)
                {
                    digit = ~temp._digits[digitIndex];
                    digitIndex++;
                    if (digitIndex == _numberLength)
                        bytesInInteger = highBytes;

                    for (int i = 0; i < bytesInInteger; i++, digit >>= 8)
                        bytes[--bytesLen] = (byte)digit;
                }
            }
            else
            {
                while (bytesLen > firstByteNumber)
                {
                    digit = temp._digits[digitIndex];
                    digitIndex++;
                    if (digitIndex == _numberLength)
                        bytesInInteger = highBytes;

                    for (int i = 0; i < bytesInInteger; i++, digit >>= 8)
                        bytes[--bytesLen] = (byte)digit;
                }
            }

            return bytes;
        }

        /// <summary>
        /// Returns this BigInteger as an double value.
        /// <para>If this is too big to be represented as an double, then Double.POSITIVE_INFINITY or Double.NEGATIVE_INFINITY} is returned.</para>
        /// </summary>
        /// 
        /// <returns>Returns this BigInteger as a double value</returns>
        /// 
        /// <remarks>
        /// Note, that not all integers x in the range [-Double.MAX_VALUE, Double.MAX_VALUE] can be represented as a double. 
        /// <para>The double representation has a mantissa of length 53. For example, <c>2^53+1 = 9007199254740993</c> is returned as double <c>9007199254740992.0</c>.</para>
        /// </remarks>
        public double ToDouble()
        {
            return Conversion.BigInteger2Double(this);
        }

        /// <summary>
        /// Returns this BigInteger as an int value. 
        /// <para>If this is too big to be represented as an int, then <c>this % 2^32</c> is returned.</para>
        /// </summary>
        /// 
        /// <returns>Returns this BigInteger as an int value</returns>
        public int ToInt32()
        {
            return (_sign * _digits[0]);
        }

        /// <summary>
        /// Returns this BigInteger as an long value. 
        /// <para>If this is too big to be represented as an long, then <c>this % 2^64</c> is returned.</para>
        /// </summary>
        /// 
        /// <returns>Returns this BigInteger as a long value</returns>
        public long ToInt64()
        {
            long value = (_numberLength > 1) ?
                (((long)_digits[1]) << 32) | (_digits[0] & 0xFFFFFFFFL) :
                (_digits[0] & 0xFFFFFFFFL);

            return (_sign * value);
        }

        /// <summary>
        /// Returns this BigInteger as an float value.
        /// <para>If this is too big to be represented as an float, then Float.POSITIVE_INFINITY 
        /// or Float.NEGATIVE_INFINITY is returned.</para>
        /// </summary>
        /// 
        /// <returns>Returns this BigInteger as a float value</returns>
        /// 
        /// <remarks>
        /// Note, that not all integers x in the range [-Float.MAX_VALUE, Float.MAX_VALUE] can be represented as a float. 
        /// The float representation has a mantissa of length 24.
        /// For example, 2^24+1 = 16777217 is returned as float 16777216.0.
        /// </remarks>
        public float ToSingle()
        {
            return (float)ToDouble();
        }

        /// <summary>
        /// Returns a string containing a string representation of this  BigInteger with base radix.
        /// <para>If Radix &lt; CharHelper.MIN_RADIX} or Radix > CharHelper.MAX_RADIX then a decimal representation is returned.
        /// The CharHelpers of the string representation are generated with method CharHelper.forDigit.</para>
        /// </summary>
        /// 
        /// <param name="Radix">Base to be used for the string representation</param>
        /// 
        /// <returns>Returns a string representation of this with radix 10</returns>
        public String ToString(int Radix)
        {
            return Conversion.BigInteger2String(this, Radix);
        }

        /// <summary>
        /// Returns a new BigInteger instance whose value is equal to Value 
        /// </summary>
        /// 
        /// <param name="Value">The value to be converted to a BigInteger</param>
        /// 
        /// <returns>Returns a BigInteger instance with the value</returns>
        public static BigInteger ValueOf(long Value)
        {
            if (Value < 0)
            {
                if (Value != -1)
                    return new BigInteger(-1, -Value);

                return MinusOne;
            }
            else if (Value <= 10)
            {
                return _smallValues[(int)Value];
            }
            else // (val > 10)
            {
                return new BigInteger(1, Value);
            }
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this ^ Value</c>
        /// </summary>
        /// 
        /// <param name="Value">Value to be xor'ed with this</param>
        /// 
        /// <returns>Returns <c>this ^ Value</c></returns>
        public BigInteger Xor(BigInteger Value)
        {
            return Logical.Xor(this, Value);
        }
        #endregion

        #region Private Methods
        internal BigInteger Copy()
        {
            // Returns a copy of the current instance to achieve immutability
            int[] copyDigits = new int[_numberLength];
            Array.Copy(_digits, 0, copyDigits, 0, _numberLength);

            return new BigInteger(_sign, _numberLength, copyDigits);
        }

        internal void CutOffLeadingZeroes()
        {
            // Decreases NumberLength if there are zero high elements
            while ((_numberLength > 0) && (_digits[--_numberLength] == 0))
            {
                // Empty
            }

            if (_digits[_numberLength++] == 0)
                _sign = 0;
        }

        private bool EqualsArrays(int[] X)
        {
            int i;
            for (i = _numberLength - 1; (i >= 0) && (_digits[i] == X[i]); i--)
            {
                // Empty
            }
            return i < 0;
        }

        internal int FirstNonzeroDigit
        {
            // Get the first non-zero digit from this
            get
            {
                if (_firstNonzeroDigit == -2)
                {
                    int i;
                    if (this._sign == 0)
                    {
                        i = -1;
                    }
                    else
                    {
                        for (i = 0; _digits[i] == 0; i++)
                        {
                            // Empty
                        }
                    }
                    _firstNonzeroDigit = i;
                }
                return _firstNonzeroDigit;
            }
        }

        internal static BigInteger GetPowerOfTwo(int Exponent)
        {
            if (Exponent < _twoPows.Length)
                return _twoPows[Exponent];

            int intCount = (int)(uint)Exponent >> 5;
            int bitN = Exponent & 31;
            int[] resDigits = new int[intCount + 1];
            resDigits[intCount] = 1 << bitN;

            return new BigInteger(1, intCount + 1, resDigits);
        }

        internal bool IsOne()
        {
            // Tests if this.Abs() is equals to ONE
            return ((_numberLength == 1) && (_digits[0] == 1));
        }

        private void PutBytesNegativeToIntegers(byte[] ByteValues)
        {
            // Puts a big-endian byte array into a little-endian applying two complement
            int bytesLen = ByteValues.Length;
            int highBytes = bytesLen & 3;
            _numberLength = ((int)(uint)bytesLen >> 2) + ((highBytes == 0) ? 0 : 1);
            _digits = new int[_numberLength];
            int i = 0;
            // Setting the sign
            _digits[_numberLength - 1] = -1;

            // Put bytes to the int array starting from the end of the byte array
            while (bytesLen > highBytes)
            {
                _digits[i] = (ByteValues[--bytesLen] & 0xFF) |
                    (ByteValues[--bytesLen] & 0xFF) << 8 |
                    (ByteValues[--bytesLen] & 0xFF) << 16 |
                    (ByteValues[--bytesLen] & 0xFF) << 24;

                if (_digits[i] != 0)
                {
                    _digits[i] = -_digits[i];
                    _firstNonzeroDigit = i;
                    i++;

                    while (bytesLen > highBytes)
                    {
                        _digits[i] = (ByteValues[--bytesLen] & 0xFF) |
                            (ByteValues[--bytesLen] & 0xFF) << 8 |
                            (ByteValues[--bytesLen] & 0xFF) << 16 |
                            (ByteValues[--bytesLen] & 0xFF) << 24;

                        _digits[i] = ~_digits[i];
                        i++;
                    }
                    break;
                }
                i++;
            }
            if (highBytes != 0)
            {
                // Put the first bytes in the highest element of the int array
                if (_firstNonzeroDigit != -2)
                {
                    for (int j = 0; j < bytesLen; j++)
                        _digits[i] = (_digits[i] << 8) | (ByteValues[j] & 0xFF);

                    _digits[i] = ~_digits[i];
                }
                else
                {
                    for (int j = 0; j < bytesLen; j++)
                        _digits[i] = (_digits[i] << 8) | (ByteValues[j] & 0xFF);

                    _digits[i] = -_digits[i];
                }
            }
        }

        private void PutBytesPositiveToIntegers(byte[] ByteValues)
        {
            // Puts a big-endian byte array into a little-endian int array
            int bytesLen = ByteValues.Length;
            int highBytes = bytesLen & 3;
            _numberLength = ((int)(uint)bytesLen >> 2) + ((highBytes == 0) ? 0 : 1);
            _digits = new int[_numberLength];
            int i = 0;

            // Put bytes to the int array starting from the end of the byte array
            while (bytesLen > highBytes)
            {
                _digits[i++] = (ByteValues[--bytesLen] & 0xFF) |
                    (ByteValues[--bytesLen] & 0xFF) << 8 |
                    (ByteValues[--bytesLen] & 0xFF) << 16 |
                    (ByteValues[--bytesLen] & 0xFF) << 24;
            }

            // Put the first bytes in the highest element of the int array
            for (int j = 0; j < bytesLen; j++)
                _digits[i] = (_digits[i] << 8) | (ByteValues[j] & 0xFF);
        }

        private static void SetFromString(BigInteger X, String Value, int Radix)
        {
            // See BigInteger(String, int)
            int sign;
            int[] digits;
            int numberLength;
            int stringLength = Value.Length;
            int startChar;
            int endChar = stringLength;

            if (Value[0] == '-')
            {
                sign = -1;
                startChar = 1;
                stringLength--;
            }
            else
            {
                sign = 1;
                startChar = 0;
            }

            // We use the following algorithm: split a string into portions of n
            // CharHelpers and convert each portion to an integer according to the
            // radix. Then convert an exp(radix, n) based number to binary using the
            // multiplication method. See D. Knuth, The Art of Computer Programming, vol. 2.
            int charsPerInt = Conversion.DigitFitInInt[Radix];
            int bigRadixDigitsLength = stringLength / charsPerInt;
            int topChars = stringLength % charsPerInt;

            if (topChars != 0)
                bigRadixDigitsLength++;

            digits = new int[bigRadixDigitsLength];
            // Get the maximal power of radix that fits in int
            int bigRadix = Conversion.BigRadices[Radix - 2];
            // Parse an input string and accumulate the BigInteger's magnitude
            int digitIndex = 0; // index of digits array
            int substrEnd = startChar + ((topChars == 0) ? charsPerInt : topChars);
            int newDigit;

            for (int substrStart = startChar; substrStart < endChar; substrStart = substrEnd, substrEnd = substrStart + charsPerInt)
            {
                int bigRadixDigit = Convert.ToInt32(Value.Substring(substrStart, substrEnd - substrStart), Radix);
                newDigit = Multiplication.MultiplyByInt(digits, digitIndex, bigRadix);
                newDigit += Elementary.InplaceAdd(digits, digitIndex, bigRadixDigit);
                digits[digitIndex++] = newDigit;
            }

            numberLength = digitIndex;
            X._sign = sign;
            X._numberLength = numberLength;
            X._digits = digits;
            X.CutOffLeadingZeroes();
        }

        internal BigInteger ShiftLeftOneBit()
        {
            return (_sign == 0) ? this : BitLevel.ShiftLeftOneBit(this);
        }

        internal void UnCache()
        {
            _firstNonzeroDigit = -2;
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Create a BigInteger from a stream
        /// </summary
        /// >
        /// <param name="Info">The serialization info</param>
        /// <param name="Context">The streaming context</param>
        private BigInteger(SerializationInfo Info, StreamingContext Context)
        {
            _sign = Info.GetInt32("sign");
            byte[] magn = (byte[])Info.GetValue("magnitude", typeof(byte[]));
            PutBytesPositiveToIntegers(magn);
            CutOffLeadingZeroes();
        }

        /// <summary>
        /// Get streaming object info
        /// </summary>
        /// 
        /// <param name="Info">The serialization info</param>
        /// <param name="Context">The streaming context</param>
        void ISerializable.GetObjectData(SerializationInfo Info, StreamingContext Context)
        {
            Info.AddValue("sign", _sign);
            byte[] magn = Abs().ToByteArray();
            Info.AddValue("magnitude", magn, typeof(byte[]));
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Returns true if Obj is a BigInteger instance and if this instance is equal to this BigInteger
        /// </summary>
        /// 
        /// <param name="Obj">Object to be compared with this</param>
        /// 
        /// <returns>Returns true if Obj is a BigInteger and this == Obj,  false otherwise</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;

            if (Obj is BigInteger)
            {
                BigInteger x1 = (BigInteger)Obj;
                return _sign == x1._sign && _numberLength == x1._numberLength && EqualsArrays(x1._digits);
            }
            return false;
        }

        /// <summary>
        /// Returns a hash code for this BigInteger
        /// </summary> 
        /// 
        /// <returns>Returns hash code for this</returns>
        public override int GetHashCode()
        {
            if (_hashCode != 0)
                return _hashCode;

            for (int i = 0; i < _digits.Length; i++)
                _hashCode = (int)(_hashCode * 33 + (_digits[i] & 0xffffffff));

            _hashCode = _hashCode * _sign;

            return _hashCode;
        }

        /// <summary>
        /// Returns a string representation of this BigInteger in decimal form
        /// </summary>
        /// 
        /// <returns>Returns a string representation of this in decimal form</returns>
        public override String ToString()
        {
            return Conversion.ToDecimalScaledString(this, 0);
        }
        #endregion

        #region IConvertible
        TypeCode IConvertible.GetTypeCode()
        {
            return TypeCode.Object;
        }

        bool IConvertible.ToBoolean(IFormatProvider Provider)
        {
            throw new NotImplementedException();
        }

        char IConvertible.ToChar(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        sbyte IConvertible.ToSByte(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        byte IConvertible.ToByte(IFormatProvider Provider)
        {
            int value = ToInt32();
            if (value > Byte.MaxValue || value < Byte.MinValue)
                throw new InvalidCastException();
            return (byte)value;
        }

        short IConvertible.ToInt16(IFormatProvider Provider)
        {
            int value = ToInt32();
            if (value > Int16.MaxValue || value < Int16.MinValue)
                throw new InvalidCastException();
            return (short)value;
        }

        ushort IConvertible.ToUInt16(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        int IConvertible.ToInt32(IFormatProvider Provider)
        {
            return ToInt32();
        }

        uint IConvertible.ToUInt32(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        long IConvertible.ToInt64(IFormatProvider Provider)
        {
            return ToInt64();
        }

        ulong IConvertible.ToUInt64(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        float IConvertible.ToSingle(IFormatProvider Provider)
        {
            return ToSingle();
        }

        double IConvertible.ToDouble(IFormatProvider Provider)
        {
            return ToDouble();
        }

        decimal IConvertible.ToDecimal(IFormatProvider Provider)
        {
            throw new NotImplementedException();
        }

        DateTime IConvertible.ToDateTime(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        string IConvertible.ToString(IFormatProvider Provider)
        {
            return ToString();
        }

        object IConvertible.ToType(Type ConversionType, IFormatProvider Provider)
        {
            if (ConversionType == typeof(byte))
                return (this as IConvertible).ToByte(Provider);
            if (ConversionType == typeof(short))
                return (this as IConvertible).ToInt16(Provider);
            if (ConversionType == typeof(int))
                return ToInt32();
            if (ConversionType == typeof(long))
                return ToInt64();
            if (ConversionType == typeof(float))
                return ToSingle();
            if (ConversionType == typeof(double))
                return ToDouble();
            if (ConversionType == typeof(string))
                return ToString();
            if (ConversionType == typeof(byte[]))
                return ToByteArray();

            throw new NotSupportedException();
        }
        #endregion

        #region Operators
        /// <summary>
        /// Returns a new BigInteger whose value is <c>A + B</c>
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A + B</c>.</returns>
        public static BigInteger operator +(BigInteger A, BigInteger B)
        {
            if (A == null || B == null)
                throw new InvalidOperationException("The value can not be null!");

            return A.Add(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>A - B</c>
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A - B</c></returns>
        public static BigInteger operator -(BigInteger A, BigInteger B)
        {
            if (A == null || B == null)
                throw new InvalidOperationException("The value can not be null!");

            return A.Subtract(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>A * B</c>
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The multiplicand value B</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A * B</c></returns>
        public static BigInteger operator *(BigInteger A, BigInteger B)
        {
            return A.Multiply(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>A / B</c>
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The divisor value B</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A / B</c></returns>
        public static BigInteger operator /(BigInteger A, BigInteger B)
        {
            return A.Divide(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>A Mod B</c>.
        /// <para>The modulus M must be positive.
        /// The result is guaranteed to be in the interval (0, M) (0 inclusive, m exclusive).
        /// The behavior of this function is not equivalent to the behavior of the % operator 
        /// defined for the built-in int's.</para>
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The modulus value B</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A Mod B</c></returns>
        public static BigInteger operator %(BigInteger A, BigInteger B)
        {
            return A.Mod(B);
        }

        /// <summary>
        /// Computes the bit per bit operator between this number and the given one
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value to be and'ed with "A"</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A &amp; B</c></returns>
        public static BigInteger operator &(BigInteger A, BigInteger B)
        {
            return A.And(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>A | B</c>
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value to be Or'ed with "A"</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A | B</c></returns>
        public static BigInteger operator |(BigInteger A, BigInteger B)
        {
            return A.Or(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>A ^ B</c>
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">Value to be xor'ed with "A"</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>A ^ B</c></returns>
        public static BigInteger operator ^(BigInteger A, BigInteger B)
        {
            return A.Xor(B);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is ~X.
        /// <para>The result of this operation is <c>-X-1</c>.</para>
        /// </summary>
        /// 
        /// <param name="X">Value to be unary reversed</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>-X-1</c></returns>
        public static BigInteger operator ~(BigInteger X)
        {
            return X.Not();
        }

        /// <summary>
        /// Returns a new BigInteger whose value is the <c>-X</c>
        /// </summary>
        /// 
        /// <param name="X">The value to be negated</param>
        /// 
        /// <returns>Returns a new BigInteger whose value is <c>-X</c></returns>
        public static BigInteger operator -(BigInteger X)
        {
            return X.Negate();
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this >> N</c>
        /// <para>For negative arguments, the result is also negative. 
        /// The shift distance may be negative which means that this is shifted left.</para>
        /// </summary>
        /// 
        /// <param name="X">The value to be shifted</param>
        /// <param name="N">The shift distance in bits</param>
        /// 
        /// <returns>Returns <c>X >> N</c>, if <c>N >= 0</c>; <c>X &lt;&lt; (-N)</c> otherwise</returns>
        public static BigInteger operator >>(BigInteger X, int N)
        {
            return X.ShiftRight(N);
        }

        /// <summary>
        /// Returns a new BigInteger whose value is this &lt;&lt; N.
        /// <para>The result is equivalent to <c>this * 2^n</c> if n >= 0.
        /// The shift distance may be negative which means that this is shifted right.
        /// The result then corresponds to <c>Floor(this / 2^(-n))</c>.</para>
        /// </summary>
        /// 
        /// <param name="X">The value to be shifted</param>
        /// <param name="N">The shift distance in bits</param>
        /// 
        /// <returns>Returns <c>X &lt;&lt; N</c> if N >= 0, <c>X >> (-N)</c> otherwise</returns>
        public static BigInteger operator <<(BigInteger X, int N)
        {
            return X.ShiftLeft(N);
        }

        /// <summary>
        /// Returns true if BigInteger value "A" is more than BigInteger value "B"
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns true if <c>A > B</c>, otherwise false</returns>
        public static bool operator >(BigInteger A, BigInteger B)
        {
            return A.CompareTo(B) < 0;
        }

        /// <summary>
        /// Returns true if BigInteger value "A" is less than BigInteger value "B"
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns true if <c>A &lt; B</c>, otherwise false</returns>
        public static bool operator <(BigInteger A, BigInteger B)
        {
            return A.CompareTo(B) > 0;
        }

        /// <summary>
        /// Returns true if "A" is a BigInteger instance and if this instance is equal to the BigInteger "B"
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns true if "B" is a BigInteger and <c>A == B</c></returns>
        public static bool operator ==(BigInteger A, BigInteger B)
        {
            if ((object)A == null && (object)B == null)
                return true;
            if ((object)A == null)
                return false;

            return A.Equals(B);
        }

        /// <summary>
        /// Returns true if BigInteger value "A" is not equal to BigInteger "B"
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns true if <c>A != B</c>, otherwise false</returns>
        public static bool operator !=(BigInteger A, BigInteger B)
        {
            return !(A == B);
        }

        /// <summary>
        /// Returns true if BigInteger value "A" is more than or equal to BigInteger value "B"
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns true if <c>A >= B</c>, otherwise false</returns>
        public static bool operator >=(BigInteger A, BigInteger B)
        {
            return A == B || A > B;
        }

        /// <summary>
        /// Returns true if BigInteger value "A" is less than or equal to BigInteger value "B"
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns true if <c>A &lt;= B</c>, otherwise false</returns>
        public static bool operator <=(BigInteger A, BigInteger B)
        {
            return A == B || A < B;
        }
        #endregion

        #region Implicit Operators
        /// <summary>
        /// Returns this BigInteger as an int value. 
        /// <para>If this is too big to be represented as an int, then <c>this % 2^32</c> is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger to convert</param>
        /// 
        /// <returns>Returns this BigInteger as an int value</returns>
        public static implicit operator Int32(BigInteger X)
        {
            return X.ToInt32();
        }

        /// <summary>
        /// Returns this BigInteger as an long value. 
        /// <para>If this is too big to be represented as an long, then <c>this % 2^64</c> is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger to convert</param>
        /// 
        /// <returns>Returns this BigInteger as a long value</returns>
        public static implicit operator Int64(BigInteger X)
        {
            return X.ToInt64();
        }

        /// <summary>
        /// Returns this BigInteger as an float value.
        /// <para>If this is too big to be represented as an float, then Float.POSITIVE_INFINITY 
        /// or Float.NEGATIVE_INFINITY is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger to convert</param>
        /// 
        /// <returns>Returns this BigInteger as a float value</returns>
        /// 
        /// <remarks>
        /// Note, that not all integers x in the range [-Float.MAX_VALUE, Float.MAX_VALUE] can be represented as a float. 
        /// The float representation has a mantissa of length 24.
        /// For example, 2^24+1 = 16777217 is returned as float 16777216.0.
        /// </remarks>
        public static implicit operator Single(BigInteger X)
        {
            return X.ToSingle();
        }

        /// <summary>
        /// Returns this BigInteger as an double value.
        /// <para>If this is too big to be represented as an double, then Double.POSITIVE_INFINITY or 
        /// Double.NEGATIVE_INFINITY} is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger to convert</param>
        /// 
        /// <returns>Returns this BigInteger as a double value</returns>
        /// 
        /// <remarks>
        /// Note, that not all integers x in the range [-Double.MAX_VALUE, Double.MAX_VALUE] can be represented as a double. 
        /// <para>The double representation has a mantissa of length 53. For example, <c>2^53+1 = 9007199254740993</c> is returned as double <c>9007199254740992.0</c>.</para>
        /// </remarks>
        public static implicit operator Double(BigInteger X)
        {
            return X.ToDouble();
        }

        /// <summary>
        /// Returns a string representation of this BigInteger in decimal form
        /// </summary>
        /// 
        /// <param name="X">The BigInteger to convert</param>
        /// 
        /// <returns>Returns a string representation of this in decimal form</returns>
        public static implicit operator String(BigInteger X)
        {
            return X.ToString();
        }

        /// <summary>
        /// Returns a new BigInteger instance whose value is equal to Value
        /// </summary>
        /// 
        /// <param name="Value">The int value to be converted to a BigInteger</param>
        /// 
        /// <returns>Returns a BigInteger instance with the value</returns>
        public static implicit operator BigInteger(int Value)
        {
            return ValueOf(Value);
        }

        /// <summary>
        /// Returns a new BigInteger instance whose value is equal to Value
        /// </summary>
        /// 
        /// <param name="Value">The long value to be converted to a BigInteger</param>
        /// 
        /// <returns>Returns a BigInteger instance with the value</returns>
        public static implicit operator BigInteger(long Value)
        {
            return ValueOf(Value);
        }
        #endregion
    }
}