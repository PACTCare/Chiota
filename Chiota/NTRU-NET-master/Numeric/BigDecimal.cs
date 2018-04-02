#region Directives
using System;
using System.Globalization;
using System.Runtime.Serialization;
using System.Text;
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
// Based on the Deveel Math library by Antonello Provenzano: <see href="https://github.com/deveel/deveel-math/tree/master/src/Deveel.Math/Deveel.Math">BigDecimal class, 
// and Open JDK <see href="http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8-b132/java/math/BigInteger.java#BigInteger">BigDecimal.java</see>.
// 
// Implementation Details:
// An implementation of a BigDecimal class. 
// Written by John Underhill, March 29, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// <h3>This class represents immutable arbitrary precision decimal numbers</h3>
    /// 
    /// 
    /// <description>Immutable, arbitrary-precision signed decimal numbers.</description> 
    /// <para>A BigDecimal consists of an arbitrary precision integer unscaled valueand a 32-bit integer scale.  
    /// If zero or positive, the scale is the number of digits to the right of the decimal point.  
    /// If negative, the unscaled value of the number is multiplied by ten to the power of the negation of the scale.  
    /// The value of the number represented by the BigDecimal is therefore (unscaledValue times; 10 pow -scale).</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Creating a BigDecimal:</description>
    /// <code>
    /// BigDecimal p = BigDecimal(bigInt);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.2.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <para>The BigDecimal class provides operations for arithmetic, scale manipulation, rounding, comparison, hashing, and format conversion.  
    /// The ToString() method provides a canonical representation of a BigDecimal.</para>
    /// 
    /// <para>The BigDecimal class gives its user complete control over rounding behavior.  
    /// If no rounding mode is specified and the exact result cannot be represented, an exception is thrown;
    /// otherwise, calculations can be carried out to a chosen precision and rounding mode by supplying an appropriate MathContext object to the operation.  
    /// In either case, eight rounding modes are provided for the control of rounding.  
    /// Using the integer fields in this class (such as HalfUp) to represent rounding mode is largely obsolete; 
    /// the enumeration values of the RoundingMode enum, (such as HalfUp) should be used instead.</para>
    /// 
    /// <para>When a MathContext object is supplied with a precision setting of 0 (for example, Unnecessary), arithmetic operations are exact, 
    /// as are the arithmetic methods which take no MathContext object. 
    /// As a corollary of computing the exact result, the rounding mode setting of a MathContext object with a precision setting of 0 is not used and thus irrelevant.  
    /// In the case of divide, the exact quotient could have an infinitely long decimal expansion; for  example, 1 divided by 3.  
    /// If the quotient has a nonterminating decimal expansion and the operation is specified to return an exact result, an ArithmeticException is thrown.  
    /// Otherwise, the exact result of the division is returned, as done for other operations.</para>
    /// 
    /// <para>When the precision setting is not 0, the rules of BigDecimal arithmetic are broadly compatible with selected 
    /// modes of operation of the arithmetic defined in ANSI X3.274-1996 and ANSI X3.274-1996/AM 1-2000 (section 7.4).  
    /// Unlike those standards, BigDecimal includes many rounding modes. Any conflicts between these ANSI standards and the BigDecimal specification are resolved in favor of BigDecimal.</para>
    /// 
    /// <para>Since the same numerical value can have different representations (with different scales), the rules of arithmetic
    /// and rounding must specify both the numerical result and the scale used in the result's representation.</para>
    /// 
    /// <para>In general the rounding modes and precision setting determine how operations return results with a limited number of digits when
    /// the exact result has more digits (perhaps infinitely many in the case of division) than the number of digits returned.</para>
    /// 
    /// <para>First, the total number of digits to return is specified by the MathContext's Precision} setting; this determines the result's <c>Precision</c>.  
    /// The digit count starts from the leftmost nonzero digit of the exact result.  The rounding mode determines how any discarded trailing digits affect the returned result.</para>
    /// 
    /// <para>For all arithmetic operators , the operation is carried out as though an exact intermediate result were first calculated and then
    /// rounded to the number of digits specified by the precision setting (if necessary), using the selected rounding mode.  
    /// If the exact result is not returned, some digit positions of the exact result are discarded.  
    /// When rounding increases the magnitude of the returned result, it is possible for a new digit position to be created by a carry propagating to a leading "9" digit.
    /// For example, rounding the value 999.9 to three digits rounding up would be numerically equal to one thousand, represented as <c>100 times 10 pow 1</c>.  
    /// In such cases, the new "1" is the leading digit position of the returned result.</para>
    /// 
    /// <para>Besides a logical exact result, each arithmetic operation has a preferred scale for representing a result.  
    /// The preferred scale for each operation is listed in the table below.</para>
    /// 
    /// <description>Preferred Scales for Results of Arithmetic Operations</description>
    /// <list type="table">
    /// <item><description>Operation: Preferred Scale of Result</description></item>
    /// <item><description>Add: Max(Addend.Scale(), Augend.Scale())</description></item>
    /// <item><description>Subtract: Max(Minuend.Scale(), Subtrahend.Scale())</description></item>
    /// <item><description>Multiply: Multiplier.Scale() + Multiplicand.Scale()</description></item>
    /// <item><description>Divide: Dividend.Scale() - Divisor.Scale()</description></item>
    /// </list>
    /// 
    /// <para>These scales are the ones used by the methods which return exact arithmetic results; 
    /// except that an exact divide may have to use a larger scale since the exact result may have more digits.  
    /// For example, <c>1/32</c> is <c>0.03125</c>.</para>
    /// 
    /// <para>Before rounding, the scale of the logical exact intermediate result is the preferred scale for that operation.  
    /// If the exact numerical result cannot be represented in Precision digits, rounding selects the set of digits to return and the scale
    /// of the result is reduced from the scale of the intermediate result to the least scale which can represent the Precision digits actually returned. 
    /// If the exact result can be represented with at most Precision digits, the representation of the result with the scale closest to the preferred scale is returned.  
    /// In particular, an exactly representable quotient may be represented in fewer than Precision digits by removing trailing zeros and decreasing the scale.  
    /// For example, rounding to three digits using the Floor rounding mode.</para>
    /// 
    /// <para>Note that for add, subtract, and multiply, the reduction in scale will equal the number of digit positions of the exact result which are discarded. 
    /// If the rounding causes a carry propagation to create a new high-order digit position, an additional digit of the result is discarded than when no new digit position is created.</para>
    /// 
    /// <para>Other methods may have slightly different rounding semantics.
    /// For example, the result of the Pow method using the Pow(int, MathContext) specified algorithm can occasionally differ from the rounded mathematical result by more
    /// than one unit in the last place, one Ulp.</para>
    /// 
    /// <para>Two types of operations are provided for manipulating the scale of a BigDecimal: scaling/rounding operations and decimal point motion operations.  
    /// Scaling/rounding operations SetScale and Round}) return a BigDecimal whose value is approximately (or exactly) equal
    /// to that of the operand, but whose scale or precision is the specified value; that is, they increase or decrease the precision
    /// of the stored number with minimal effect on its value.  
    /// Decimal point motion operations (MovePointLeft and MovePointRight) return a BigDecimal created from the operand by moving the decimal point a specified distance in the specified direction.</para>
    /// 
    /// Each BigDecimal instance is represented with a unscaled arbitrary precision mantissa (the unscaled value) and a scale. 
    /// <para>The value of the "BigDecimal is <see cref="UnScaledValue"/> 10^(-<see cref="Scale"/>).
    /// Since the ToString() method is overriden by this class and it changes the state of the object causing Heisenbugs
    /// for debuggability we add the attribute DebuggerDisplay that points to a method that doesn't change it.</para>
    /// </remarks>
    [Serializable]
    [System.Diagnostics.DebuggerDisplay("{ToStringInternal()}")]
    public class BigDecimal : IComparable<BigDecimal>, IConvertible, ISerializable
    {
        #region Constants
        // The bi scaled by zero length
        private const int BISCALEDZERO_LEN = 11;
        // The double closer to Log10(2)
        private const double LOG10_2 = 0.3010299956639812;
        #endregion

        #region Public Fields
        /// <summary>
        /// The constant zero as a <see cref="BigDecimal"/>.
        /// </summary>
        public static readonly BigDecimal Zero = new BigDecimal(0, 0);

        /// <summary>
        /// The constant one as a <see cref="BigDecimal"/>.
        /// </summary>
        public static readonly BigDecimal One = new BigDecimal(1, 0);

        /// <summary>
        /// The constant ten as a <see cref="BigDecimal"/>.
        /// </summary>
        public static readonly BigDecimal Ten = new BigDecimal(10, 0);
        #endregion

        #region Private Fields
        // The string representation is cached
        [NonSerialized]
        private string _toStringImage;
        // Cache for the hash code
        [NonSerialized]
        private int _hashCode;
        // An array with powers of five that fit in the type long (5^0,5^1,...,5^27).
        private static readonly BigInteger[] _fivePow;
        // An array with powers of ten that fit in the type long (10^0,10^1,...,10^18).
        private static readonly BigInteger[] _tenPow;
        // An array with powers of ten that fit in the type long (10^0,10^1,...,10^18).
        private static readonly long[] _longTenPow = {
                                                        1L, 10L, 100L, 1000L, 10000L, 100000L, 1000000L, 10000000L, 
                                                        100000000L, 1000000000L, 10000000000L, 100000000000L, 
                                                        1000000000000L, 10000000000000L, 100000000000000L, 
                                                        1000000000000000L, 10000000000000000L, 100000000000000000L, 
                                                        1000000000000000000L, 
                                                    };
        // The long five pow.
        private static readonly long[] _longFivePow = {
                                                         1L, 5L, 25L, 125L, 625L, 3125L, 15625L, 78125L, 390625L, 
                                                         1953125L, 9765625L, 48828125L, 244140625L, 1220703125L, 
                                                         6103515625L, 30517578125L, 152587890625L, 762939453125L, 
                                                         3814697265625L, 19073486328125L, 95367431640625L, 
                                                         476837158203125L, 2384185791015625L, 11920928955078125L, 
                                                         59604644775390625L, 298023223876953125L, 1490116119384765625L, 
                                                         7450580596923828125L, 
                                                     };

        // The long five pow bit length.
        private static readonly int[] _longFivePowBitLength = new int[_longFivePow.Length];
        // The long ten pow bit length
        private static readonly int[] _longTenPowBitLength = new int[_longTenPow.Length];
        // An array with the first BigInteger scaled by zero ([0,0],[1,0],...,[10,0]).
        private static readonly BigDecimal[] _biScaledByZero = new BigDecimal[BISCALEDZERO_LEN];
        // An array with the zero number scaled by the first positive scales. (0*10^0, 0*10^1, ..., 0*10^10).
        private static readonly BigDecimal[] _zeroScaledBy = new BigDecimal[11];
        // An array filled with character '0'
        private static readonly char[] _chZeros = new char[100];
        // The arbitrary precision integer (unscaled value) in the internal representation of BigDecimal
        private BigInteger _intVal;
        // The bit length.
        [NonSerialized]
        private int _bitLength;
        // The small value
        [NonSerialized]
        private long _smallValue;
        // The 32-bit integer scale in the internal representation of BigDecimal
        private int _scale;
        // Represent the number of decimal digits in the unscaled value.
        [NonSerialized]
        private int _precision = 0;
        #endregion

        #region Properies
        /// <summary>
        /// Returns the precision of this BigDecimal.
        /// <para>The precision is the number of decimal digits used to represent this decimal.
        /// It is equivalent to the number of digits of the unscaled value.
        /// The precision of 0 is 1 (independent of the scale).</para>
        /// </summary>
        public int Precision
        {
            get
            {
                // Checking if the precision already was calculated
                if (_precision > 0)
                    return _precision;

                int bitLength = _bitLength;
                int decimalDigits = 1; // the precision to be calculated
                double doubleUnsc = 1; // intVal in 'double'

                if (bitLength < 1024)
                {
                    // To calculate the precision for small numbers
                    if (bitLength >= 64)
                        doubleUnsc = GetUnscaledValue().ToDouble();
                    else if (bitLength >= 1)
                        doubleUnsc = _smallValue;

                    var val = (int)Math.Round(System.Math.Log10(System.Math.Abs(doubleUnsc)));
                    decimalDigits = val == 0 ? 1 : val + 1;
                }
                else
                {
                    // To calculate the precision for large numbers
                    //Note that: 2 ^(bitlength() - 1) <= intVal < 10 ^(precision())
                    decimalDigits += (int)((bitLength - 1) * LOG10_2);

                    // If after division the number isn't zero, exists an aditional digit
                    if (GetUnscaledValue().Divide(Multiplication.PowerOf10(decimalDigits)).Signum() != 0)
                        decimalDigits++;
                }

                _precision = decimalDigits;
                return _precision;
            }
        }

        /// <summary>
        /// Returns the scale of this BigDecimal.
        /// <para>The scale is the number of digits behind the decimal point.
        /// The value of this BigDecimal is the unsignedValue * 10^(-scale). 
        /// If the scale is negative, then this BigDecimal represents a big integer.</para>
        /// </summary>
        public int Scale
        {
            get { return _scale; }
        }

        /// <summary>
        /// Returns the unscaled value (mantissa) of this BigDecimal instance as a BigInteger.
        /// <para>The unscaled value can be computed as this <c>10^(scale)</c>.</para>
        /// </summary>
        public BigInteger UnScaledValue
        {
            get { return GetUnscaledValue(); }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes static members of the BigDecimal class.
        /// </summary>
        static BigDecimal()
        {
            // To fill all static arrays.
            int i = 0;

            for (; i < _zeroScaledBy.Length; i++)
            {
                _biScaledByZero[i] = new BigDecimal(i, 0);
                _zeroScaledBy[i] = new BigDecimal(0, i);
                _chZeros[i] = '0';
            }

            for (; i < _chZeros.Length; i++)
                _chZeros[i] = '0';

            for (int j = 0; j < _longFivePowBitLength.Length; j++)
                _longFivePowBitLength[j] = BitLength(_longFivePow[j]);

            for (int j = 0; j < _longTenPowBitLength.Length; j++)
                _longTenPowBitLength[j] = BitLength(_longTenPow[j]);

            // Taking the references of useful powers.
            _tenPow = Multiplication.bigTenPows;
            _fivePow = Multiplication.bigFivePows;
        }

        /// <summary>
        /// Translates a character array representation of a BigDecimal into a BigDecimal, 
        /// accepting the same sequence of characters as the BigDecimal(String) constructor,
        /// while allowing a sub-array to be specified.
        /// <para>Note that if the sequence of characters is already available within a character array, 
        /// using this constructor is faster than converting the char array to string and using the BigDecimal(String) constructor.</para>
        /// </summary>
        /// 
        /// <param name="Data">Array that is the source of characters</param>
        /// <param name="Offset">Offset first character in the array to inspect.</param>
        /// <param name="Length">Number of characters to consider.</param>
        /// 
        /// <exception cref="ArgumentNullException">Thrown if a null data array is passed</exception>
        /// <exception cref="FormatException">Thrown if an invalid char array is passed, or scale is out of range</exception>
        public BigDecimal(char[] Data, int Offset, int Length)
        {
            int begin = Offset; // first index to be copied
            int last = Offset + (Length - 1); // last index to be copied

            if (Data == null)
                throw new ArgumentNullException("Data can not be null!");

            if ((last >= Data.Length) || (Offset < 0) || (Length <= 0) || (last < 0))
                throw new FormatException("Char array is not a valid Bigdecimal format!");

            StringBuilder unscaledBuffer = new StringBuilder(Length);
            int bufLength = 0;

            // To skip a possible '+' symbol
            if ((Offset <= last) && (Data[Offset] == '+'))
            {
                Offset++;
                begin++;
            }

            int counter = 0;
            bool wasNonZero = false;

            // Accumulating all digits until a possible decimal point
            for (; (Offset <= last) && (Data[Offset] != '.') && (Data[Offset] != 'e') && (Data[Offset] != 'E'); Offset++)
            {
                if (!wasNonZero)
                {
                    if (Data[Offset] == '0')
                        counter++;
                    else
                        wasNonZero = true;
                }
            }

            unscaledBuffer.Append(Data, begin, Offset - begin);
            bufLength += Offset - begin;

            // A decimal point was found
            if ((Offset <= last) && (Data[Offset] == '.'))
            {
                Offset++;

                // Accumulating all digits until a possible exponent
                begin = Offset;
                for (; (Offset <= last) && (Data[Offset] != 'e') && (Data[Offset] != 'E'); Offset++)
                {
                    if (!wasNonZero)
                    {
                        if (Data[Offset] == '0')
                            counter++;
                        else
                            wasNonZero = true;
                    }
                }

                _scale = Offset - begin;
                bufLength += _scale;
                unscaledBuffer.Append(Data, begin, _scale);
            }
            else
            {
                _scale = 0;
            }

            // An exponent was found
            if ((Offset <= last) && ((Data[Offset] == 'e') || (Data[Offset] == 'E')))
            {
                Offset++;

                // Checking for a possible sign of scale
                begin = Offset;
                if ((Offset <= last) && (Data[Offset] == '+'))
                {
                    Offset++;

                    if ((Offset <= last) && (Data[Offset] != '-'))
                        begin++;
                }

                // Accumulating all remaining digits
                string scaleString = new String(Data, begin, last + 1 - begin); // buffer for scale
                // Checking if the scale is defined            
                long newScale = (long)_scale - int.Parse(scaleString); // the new scale
                _scale = (int)newScale;

                if (newScale != _scale)
                    throw new FormatException("Scale out of range!");
            }

            // Parsing the unscaled value
            if (bufLength < 19)
            {
                _smallValue = long.Parse(unscaledBuffer.ToString());
                _bitLength = BitLength(_smallValue);
            }
            else
            {
                SetUnscaledValue(new BigInteger(unscaledBuffer.ToString()));
            }

            _precision = unscaledBuffer.Length - counter;

            if (unscaledBuffer[0] == '-')
                _precision--;
        }

        /// <summary>
        /// Translates a character array representation of a BigDecimal into a BigDecimal,
        /// accepting the same sequence of characters as the BigDecimal(String)constructor,
        /// while allowing a sub-array to be specified and with rounding according to the context settings.
        /// <para>Note that if the sequence of characters is already available within a character array,
        /// using this constructor is faster than converting the char array to string and using the BigDecimal(String) constructor.</para>
        /// </summary>
        /// 
        /// <param name="Data">The source of characters used to build the BigDecimal</param>
        /// <param name="Offset">Offset of the first character in the array to inspect</param>
        /// <param name="Length">Number of characters to consider</param>
        /// <param name="Context">The context to use</param>
        public BigDecimal(char[] Data, int Offset, int Length, MathContext Context)
            : this(Data, Offset, Length)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Translates a character array representation of a BigDecimal into a BigDecimal,
        /// accepting the same sequence of characters as the BigDecimal(String)constructor,
        /// while allowing a sub-array to be specified and with rounding according to the context settings.
        /// <para>Note that if the sequence of characters is already available within a character array,
        /// using this constructor is faster than converting the char array to string and using the BigDecimal(String) constructor.</para>
        /// </summary>
        /// 
        /// <param name="Data">The source of characters used to build the BigDecimal</param>
        public BigDecimal(char[] Data)
            : this(Data, 0, Data.Length)
        {
        }

        /// <summary>
        /// Translates a character array representation of a BigDecimal into a BigDecimal,
        /// accepting the same sequence of characters as the BigDecimal(String)constructor,
        /// while allowing a sub-array to be specified and with rounding according to the context settings.
        /// <para>Note that if the sequence of characters is already available within a character array,
        /// using this constructor is faster than converting the char array to string and using the BigDecimal(String) constructor.</para>
        /// </summary>
        /// 
        /// <param name="Data">The source of characters used to build the BigDecimal</param>
        /// <param name="Context">The context to use</param>
        public BigDecimal(char[] Data, MathContext Context)
            : this(Data, 0, Data.Length)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Translates a string representation of a BigDecimal into a BigDecimal
        /// </summary>
        /// 
        /// <param name="Value">The source string used to build the BigDecimal</param>
        public BigDecimal(string Value)
            : this(Value.ToCharArray(), 0, Value.Length)
        {
        }

        /// <summary>
        /// Translates a string representation of a BigDecimal into a BigDecimal
        /// </summary>
        /// 
        /// <param name="Value">The source string used to build the BigDecimal</param>
        /// <param name="Context">The context to use</param>
        public BigDecimal(string Value, MathContext Context)
            : this(Value.ToCharArray(), 0, Value.Length)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Constructs a new <see cref="BigDecimal"/> instance from the 64bit double value. 
        /// <para>The constructed big decimal is equivalent to the given double.</para>
        /// </summary>
        /// 
        /// <param name="Value">The double value to be converted to a <see cref="BigDecimal"/> instance</param>
        /// 
        /// <remarks>
        /// For example, <c>new BigDecimal(0.1)</c> is equal to <c>0.1000000000000000055511151231257827021181583404541015625</c>. 
        /// This happens as <c>0.1</c> cannot be represented exactly in binary.
        /// <para>To generate a big decimal instance which is equivalent to <c>0.1</c> use the <see cref="BigDecimal(string)"/> constructor.</para>
        /// </remarks>
        /// 
        /// <exception cref="FormatException">Thown if <paramref name="Value"/> is infinity or not a number.</exception>
        public BigDecimal(double Value)
        {
            if (double.IsInfinity(Value) || double.IsNaN(Value))
                throw new FormatException("Value Infinity or NaN!");

            long bits = BitConverter.DoubleToInt64Bits(Value); // IEEE-754

            System.Diagnostics.Debug.Assert(bits == DoubleToLongBits(Value));
            long mantisa;
            int trailingZeros;

            // Extracting the exponent, note that the bias is 1023
            _scale = 1075 - (int)((bits >> 52) & 0x7FFL);

            // Extracting the 52 bits of the mantisa.
            mantisa = (_scale == 1075) ?
                (bits & 0xFFFFFFFFFFFFFL) << 1 :
                (bits & 0xFFFFFFFFFFFFFL) | 0x10000000000000L;

            if (mantisa == 0)
            {
                _scale = 0;
                _precision = 1;
            }

            // To simplify all factors '2' in the mantisa 
            if (_scale > 0)
            {
                trailingZeros = System.Math.Min(_scale, IntUtils.NumberOfTrailingZeros(mantisa));
                long mantisa2 = (long)(((ulong)mantisa) >> trailingZeros);
                mantisa = IntUtils.URShift(mantisa, trailingZeros);
                _scale -= trailingZeros;
            }

            // Calculating the new unscaled value and the new scale
            if ((bits >> 63) != 0)
                mantisa = -mantisa;

            int mantisaBits = BitLength(mantisa);
            if (_scale < 0)
            {
                _bitLength = mantisaBits == 0 ? 0 : mantisaBits - _scale;

                if (_bitLength < 64)
                    _smallValue = mantisa << (-_scale);
                else
                    _intVal = BigInteger.ValueOf(mantisa).ShiftLeft(-_scale);

                _scale = 0;
            }
            else if (_scale > 0)
            {
                // m * 2^e =  (m * 5^(-e)) * 10^e
                if (_scale < _longFivePow.Length && mantisaBits + _longFivePowBitLength[_scale] < 64)
                {
                    _smallValue = mantisa * _longFivePow[_scale];
                    _bitLength = BitLength(_smallValue);
                }
                else
                {
                    SetUnscaledValue(Multiplication.MultiplyByFivePow(BigInteger.ValueOf(mantisa), _scale));
                }
            }
            else
            {
                // scale == 0
                _smallValue = mantisa;
                _bitLength = mantisaBits;
            }
        }

        /// <summary>
        /// Constructs a new <see cref="BigDecimal"/> instance from the 64bit double value. 
        /// <para>The constructed big decimal is equivalent to the given double.</para>
        /// </summary>
        /// 
        /// <param name="Value">The double value to be converted to a <see cref="BigDecimal"/> instance.</param>
        /// <param name="Context">The context to use</param>
        /// 
        /// <remarks>
        /// For example, <c>new BigDecimal(0.1)</c> is equal to <c>0.1000000000000000055511151231257827021181583404541015625</c>. 
        /// This happens as <c>0.1</c> cannot be represented exactly in binary.
        /// <para>To generate a big decimal instance which is equivalent to <c>0.1</c> use the <see cref="BigDecimal(string)"/> constructor.</para>
        /// </remarks>
        public BigDecimal(double Value, MathContext Context)
            : this(Value)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given BigInteger value.
        /// <para>The scale of the result is 0</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be converted to a BigDecimal instance</param>
        public BigDecimal(BigInteger Value)
            : this(Value, 0)
        {
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given BigInteger value.
        /// <para>The scale of the result is 0</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be converted to a BigDecimal instance</param>
        /// <param name="Context">The context to use</param>
        public BigDecimal(BigInteger Value, MathContext Context)
            : this(Value)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from a given unscaled value and a given scale.
        /// <para>The value of this instance is 10^-scale</para>
        /// </summary>
        /// 
        /// <param name="UnscaledValue">Representing the unscaled value of this BigDecimal instance</param>
        /// <param name="Scale">Scale of this BigDecimal instance</param>
        /// 
        /// <exception cref="NullReferenceException">Throws if UnscaledValue == null</exception>
        public BigDecimal(BigInteger UnscaledValue, int Scale)
        {
            if (UnscaledValue == null)
                throw new NullReferenceException("UnscaledValue can not be null or empty!");

            _scale = Scale;
            SetUnscaledValue(UnscaledValue);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from a given unscaled value and a given scale.
        /// <para>The value of this instance is 10^(-scale). 
        /// The result is rounded according to the specified math context</para>
        /// </summary>
        /// 
        /// <param name="UnscaledValue">Representing the unscaled value of this BigDecimal instance</param>
        /// <param name="Scale">Scale of this BigDecimal instance</param>
        /// <param name="Context">The context to use</param>
        public BigDecimal(BigInteger UnscaledValue, int Scale, MathContext Context)
            : this(UnscaledValue, Scale)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given int value.
        /// <para>The scale of the result is 0.</para>
        /// </summary>
        /// 
        /// <param name="Value">The int value to be converted to a BigDecimal instance</param>
        public BigDecimal(int Value)
            : this(Value, 0)
        {
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given int value.
        /// <para>The scale of the result is 0. The result is rounded according to the specified math context.</para>
        /// </summary>
        /// 
        /// <param name="Value">The int value to be converted to a BigDecimal instance</param>
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        public BigDecimal(int Value, MathContext Context)
            : this(Value, 0)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given long value.
        /// <para>The scale of the result is 0.</para>
        /// </summary>
        /// 
        /// <param name="Value">The long value to be converted to a BigDecimal instance</param>
        public BigDecimal(long Value)
            : this(Value, 0)
        {
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given long value.
        /// <para>The scale of the result is 0.
        /// The result is rounded according to the specified math context.</para>
        /// </summary>
        /// 
        /// <param name="Value">The long value to be converted to a BigDecimal instance</param>
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        public BigDecimal(long Value, MathContext Context)
            : this(Value)
        {
            InplaceRound(Context);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BigDecimal"/> class.
        /// </summary>
        /// 
        /// <param name="SmallValue">The small value</param>
        /// <param name="Scale">The scale</param>
        private BigDecimal(long SmallValue, int Scale)
        {
            _smallValue = SmallValue;
            _scale = Scale;
            _bitLength = BitLength(SmallValue);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BigDecimal"/> class.
        /// </summary>
        /// 
        /// <param name="SmallValue">The small value</param>
        /// <param name="Scale">The scale</param>
        private BigDecimal(int SmallValue, int Scale)
        {
            _smallValue = SmallValue;
            _scale = Scale;
            _bitLength = BitLength(SmallValue);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns a new BigDecimal whose value is the absolute value of this.
        /// <para>The scale of the result is the same as the scale of Abs(this).</para>
        /// </summary>
        /// 
        /// <returns>
        /// <c>Abs(this)</c>
        /// </returns>
        public BigDecimal Abs()
        {
            return (Signum() < 0) ? Negate() : this;
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is the absolute value of this.
        /// <para>The result is rounded according to the passed context.</para>
        /// </summary>
        /// 
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// <c>Abs(this)</c>
        /// </returns>
        public BigDecimal Abs(MathContext Context)
        {
            return Round(Context).Abs();
        }

        /// <summary>
        /// Adds a value to the current instance of <see cref="BigDecimal"/>.
        /// <para>The scale of the result is the maximum of the scales of the two arguments.</para>
        /// </summary>
        /// 
        /// <param name="Augend">The value to be added to this instance</param>
        /// 
        /// <returns>
        /// Returns a new BigDecimal whose value is <c>this + <paramref name="Augend"/></c>.
        /// </returns>
        /// 
        /// <exception cref="ArgumentNullException">Thrown if the given <paramref name="Augend"/> is <c>null</c>.</exception>
        public BigDecimal Add(BigDecimal Augend)
        {
            int diffScale = _scale - Augend._scale;

            // Fast return when some operand is zero
            if (IsZero())
            {
                if (diffScale <= 0)
                    return Augend;
                if (Augend.IsZero())
                    return this;
            }
            else if (Augend.IsZero())
            {
                if (diffScale >= 0)
                    return this;
            }

            // Let be: this = [u1,s1]  and  augend = [u2,s2]
            if (diffScale == 0)
            {
                // case s1 == s2: [u1 + u2 , s1]
                if (System.Math.Max(_bitLength, Augend._bitLength) + 1 < 64)
                    return ValueOf(_smallValue + Augend._smallValue, _scale);

                return new BigDecimal(GetUnscaledValue().Add(Augend.GetUnscaledValue()), _scale);
            }

            // case s1 > s2 : [(u1 + u2) * 10 ^ (s1 - s2) , s1]
            if (diffScale > 0)
                return AddAndMult10(this, Augend, diffScale);

            // case s2 > s1 : [(u2 + u1) * 10 ^ (s2 - s1) , s2]
            return AddAndMult10(Augend, this, -diffScale);
        }

        /// <summary>
        /// Adds a value to the current instance of <see cref="BigDecimal"/>.
        /// <para>The result is rounded according to the passed context.</para>
        /// </summary>
        /// 
        /// <param name="Augend">The value to be added to this instance</param>
        /// <param name="Context">The rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// Returns a new BigDecimal whose value is <c>this + <paramref name="Augend"/></c>.
        /// </returns>
        /// 
        /// <exception cref="ArgumentNullException">Thrown if the given <paramref name="Augend"/> or <paramref name="Context"/> is <c>null</c>.</exception>
        public BigDecimal Add(BigDecimal Augend, MathContext Context)
        {
            BigDecimal larger; // operand with the largest unscaled value
            BigDecimal smaller; // operand with the smallest unscaled value
            BigInteger tempBI;
            long diffScale = (long)_scale - Augend._scale;
            int largerSignum;

            // Some operand is zero or the precision is infinity  
            if (Augend.IsZero() || (IsZero()) || (Context.Precision == 0))
                return Add(Augend).Round(Context);

            // Cases where there is room for optimizations
            if (AproxPrecision() < diffScale - 1)
            {
                larger = Augend;
                smaller = this;
            }
            else if (Augend.AproxPrecision() < -diffScale - 1)
            {
                larger = this;
                smaller = Augend;
            }
            else
            {
                // No optimization is done 
                return Add(Augend).Round(Context);
            }

            // No optimization is done
            if (Context.Precision >= larger.AproxPrecision())
                return Add(Augend).Round(Context);

            // Cases where it's unnecessary to add two numbers with very different scales 
            largerSignum = larger.Signum();
            if (largerSignum == smaller.Signum())
            {
                tempBI = Multiplication.MultiplyByPositiveInt(larger.GetUnscaledValue(), 10).Add(BigInteger.ValueOf(largerSignum));
            }
            else
            {
                tempBI = larger.GetUnscaledValue().Subtract(BigInteger.ValueOf(largerSignum));
                tempBI = Multiplication.MultiplyByPositiveInt(tempBI, 10).Add(BigInteger.ValueOf(largerSignum * 9));
            }

            // Rounding the improved adding 
            larger = new BigDecimal(tempBI, larger._scale + 1);

            return larger.Round(Context);
        }

        /// <summary>
        /// Add and Multiply by 10
        /// </summary>
        /// 
        /// <param name="Value">The value to add and multiply</param>
        /// <param name="Augend">The value to be added</param>
        /// <param name="DiffScale">The differential scale</param>
        /// 
        /// <returns>
        /// The result of the Add and Multiply operation
        /// </returns>
        private static BigDecimal AddAndMult10(BigDecimal Value, BigDecimal Augend, int DiffScale)
        {
            if (DiffScale < _longTenPow.Length && System.Math.Max(Value._bitLength, Augend._bitLength + _longTenPowBitLength[DiffScale]) + 1 < 64)
                return ValueOf(Value._smallValue + Augend._smallValue * _longTenPow[DiffScale], Value._scale);

            return new BigDecimal(Value.GetUnscaledValue().Add(Multiplication.MultiplyByTenPow(Augend.GetUnscaledValue(), DiffScale)), Value._scale);
        }

        /// <summary>
        /// Compares this BigDecimal with Value.
        /// <para>Returns one of the three values 1, 0, or -1.
        /// The method behaves as if Subtract(Value) is computed.
        /// If this difference is > 0 then 1 is returned, if the difference is &lt; 0 then -1 is returned, 
        /// and if the difference is 0 then 0 is returned.
        /// This means, that if two decimal instances are compared which are equal in value but differ in scale, 
        /// then these two instances are considered as equal.</para>
        /// </summary>
        /// <param name="Value">Value to be compared with this</param>
        /// 
        /// <returns>
        /// ReturnS 1 if this > Value, -1 if this &lt; Value, 0 if this == Value
        /// </returns>
        public int CompareTo(BigDecimal Value)
        {
            int thisSign = Signum();
            int valueSign = Value.Signum();

            if (thisSign == valueSign)
            {
                if (_scale == Value._scale && _bitLength < 64 && Value._bitLength < 64)
                {
                    return (_smallValue < Value._smallValue) ? -1 : (_smallValue > Value._smallValue) ? 1 : 0;
                }

                long diffScale = (long)_scale - Value._scale;
                int diffPrecision = AproxPrecision() - Value.AproxPrecision();
                if (diffPrecision > diffScale + 1)
                {
                    return thisSign;
                }
                else if (diffPrecision < diffScale - 1)
                {
                    return -thisSign;
                }
                else
                {
                    // thisSign == val.signum()  and  diffPrecision is aprox. diffScale
                    BigInteger thisUnscaled = GetUnscaledValue();
                    BigInteger valUnscaled = Value.GetUnscaledValue();

                    // If any of both precision is bigger, append zeros to the shorter one
                    if (diffScale < 0)
                    {
                        thisUnscaled = thisUnscaled.Multiply(Multiplication.PowerOf10(-diffScale));
                    }
                    else if (diffScale > 0)
                    {
                        valUnscaled = valUnscaled.Multiply(Multiplication.PowerOf10(diffScale));
                    }

                    return thisUnscaled.CompareTo(valUnscaled);
                }
            }
            else if (thisSign < valueSign)
            {
                return -1;
            }
            else
            {
                return 1;
            }
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this / divisor</c>.
        /// <para>The scale of the result is the difference of the scales of this and Divisor.
        /// If the exact result requires more digits, then the scale is adjusted accordingly.
        /// For example, <c>1/128 = 0.0078125</c> which has a scale of 7 and precision 5.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns>
        /// <c>this / divisor</c>
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if Divisor == 0 or the result cannot be represented exactly.</exception>
        public BigDecimal Divide(BigDecimal Divisor)
        {
            BigInteger p = GetUnscaledValue();
            BigInteger q = Divisor.GetUnscaledValue();
            // greatest common divisor between 'p' and 'q'
            BigInteger gcd;
            BigInteger[] quotAndRem;
            long diffScale = (long)_scale - Divisor._scale;
            // the new scale for  quotient
            int newScale;
            // number of factors "2" in 'q'
            int k;
            // number of factors "5" in 'q'
            int l = 0;
            int i = 1;
            int lastPow = _fivePow.Length - 1;

            if (Divisor.IsZero())
                throw new ArithmeticException("Division by zero");

            if (p.Signum() == 0)
                return GetZeroScaledBy(diffScale);

            // To divide both by the GCD
            gcd = p.Gcd(q);
            p = p.Divide(gcd);
            q = q.Divide(gcd);
            // To simplify all "2" factors of q, dividing by 2^k
            k = q.LowestSetBit;
            q = q.ShiftRight(k);

            // To simplify all "5" factors of q, dividing by 5^l
            do
            {
                quotAndRem = q.DivideAndRemainder(_fivePow[i]);
                if (quotAndRem[1].Signum() == 0)
                {
                    l += i;
                    if (i < lastPow)
                        i++;

                    q = quotAndRem[0];
                }
                else
                {
                    if (i == 1)
                        break;

                    i = 1;
                }
            }
            while (true);

            // If  abs(q) != 1  then the quotient is periodic
            if (!q.Abs().Equals(BigInteger.One))
                throw new ArithmeticException("Non-terminating decimal expansion; no exact representable decimal result");

            // The sign of the is fixed and the quotient will be saved in 'p'
            if (q.Signum() < 0)
                p = p.Negate();

            // Checking if the new scale is out of range
            newScale = ToIntScale(diffScale + System.Math.Max(k, l));
            // k >= 0  and  l >= 0  implies that  k - l  is in the 32-bit range
            i = k - l;

            p = (i > 0) ? Multiplication.MultiplyByFivePow(p, i) : p.ShiftLeft(-i);
            return new BigDecimal(p, newScale);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this / divisor</c>.
        /// <para>The result is rounded according to the passed context.
        /// If the passed math context specifies precision 0, then this call is equivalent to <c>Divide(Divisor)</c></para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// <c>this / divisor</c>
        /// </returns>
        public BigDecimal Divide(BigDecimal Divisor, MathContext Context)
        {
            // Calculating how many zeros must be append to 'dividend'
            // to obtain a  quotient with at least 'mc.precision()' digits 
            long traillingZeros = Context.Precision + 2L + Divisor.AproxPrecision() - AproxPrecision();
            long diffScale = (long)_scale - Divisor._scale;
            long newScale = diffScale; // scale of the  quotient
            int compRem; // to compare the remainder
            int i = 1; // index   
            int lastPow = _tenPow.Length - 1; // last power of ten
            BigInteger integerQuot; // for temporal results
            BigInteger[] quotAndRem = { GetUnscaledValue() };

            // In special cases it reduces the problem to call the dual method
            if ((Context.Precision == 0) || IsZero() || Divisor.IsZero())
                return Divide(Divisor);

            if (traillingZeros > 0)
            {
                // To append trailing zeros at end of dividend
                quotAndRem[0] = GetUnscaledValue().Multiply(Multiplication.PowerOf10(traillingZeros));
                newScale += traillingZeros;
            }

            quotAndRem = quotAndRem[0].DivideAndRemainder(Divisor.GetUnscaledValue());
            integerQuot = quotAndRem[0];

            // Calculating the exact quotient with at least 'mc.precision()' digits
            if (quotAndRem[1].Signum() != 0)
            {
                // Checking if:   2 * remainder >= divisor ?
                compRem = quotAndRem[1].ShiftLeftOneBit().CompareTo(Divisor.GetUnscaledValue());
                // quot := quot * 10 + r;     with 'r' in {-6,-5,-4, 0,+4,+5,+6}
                integerQuot = integerQuot.Multiply(BigInteger.Ten).Add(BigInteger.ValueOf(quotAndRem[0].Signum() * (5 + compRem)));
                newScale++;
            }
            else
            {
                // To strip trailing zeros until the preferred scale is reached
                while (!integerQuot.TestBit(0))
                {
                    quotAndRem = integerQuot.DivideAndRemainder(_tenPow[i]);
                    if ((quotAndRem[1].Signum() == 0) && (newScale - i >= diffScale))
                    {
                        newScale -= i;
                        if (i < lastPow)
                            i++;

                        integerQuot = quotAndRem[0];
                    }
                    else
                    {
                        if (i == 1)
                            break;

                        i = 1;
                    }
                }
            }

            // To perform rounding
            return new BigDecimal(integerQuot, ToIntScale(newScale), Context);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this / divisor</c>.
        /// <para>The scale of the result is the scale of this.
        /// If rounding is required to meet the specified scale, then the specified rounding mode is applied.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="RoundMode">Rounding mode to be used to round the result</param>
        /// 
        /// <returns>
        /// <c>this / divisor</c> rounded according to the given rounding mode
        /// </returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if an invalid rounding mode is used</exception>
        public BigDecimal Divide(BigDecimal Divisor, int RoundMode)
        {
            if (!Enum.IsDefined(typeof(RoundingModes), RoundMode))
                throw new ArgumentException("Invalid rounding mode!");

            return Divide(Divisor, _scale, (RoundingModes)RoundMode);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this / divisor</c>.
        /// <para>As scale of the result the parameter Scale is used.
        /// If rounding is required to meet the specified scale, then the specified rounding mode is applied.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="Scale">The scale of the result returned</param>
        /// <param name="RoundMode">Rounding mode to be used to round the result</param>
        /// 
        /// <returns>
        /// <c>this / divisor</c> rounded according to the given rounding mode
        /// </returns>
        public BigDecimal Divide(BigDecimal Divisor, int Scale, int RoundMode)
        {
            return Divide(Divisor, Scale, (RoundingModes)RoundMode);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this / divisor</c>.
        /// <para>The scale of the result is the scale of this.
        /// If rounding is required to meet the specified scale, then the specified rounding mode is applied.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="RoundingMode">Rounding mode to be used to round the result</param>
        /// 
        /// <returns>
        /// <c>this / divisor</c> rounded according to the given rounding
        /// </returns>
        public BigDecimal Divide(BigDecimal Divisor, RoundingModes RoundingMode)
        {
            return Divide(Divisor, _scale, RoundingMode);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this / divisor</c>.
        /// <para>As scale of the result the parameter Scale is used.
        /// If rounding is required to meet the specified scale, then the specified rounding mode is applied.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="Scale">The scale of the result returned</param>
        /// <param name="RoundingMode">Rounding mode to be used to round the result</param>
        /// 
        /// <returns>
        /// <c>this / divisor</c> rounded according to the given rounding mode
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if Divisor == 0</exception>
        public BigDecimal Divide(BigDecimal Divisor, int Scale, RoundingModes RoundingMode)
        {
            // Let be: this = [u1,s1]  and  divisor = [u2,s2]
            if (Divisor.IsZero())
                throw new ArithmeticException("Division by zero!");

            long diffScale = ((long)_scale - Divisor._scale) - Scale;
            if (_bitLength < 64 && Divisor._bitLength < 64)
            {
                if (diffScale == 0)
                    return DividePrimitiveLongs(_smallValue, Divisor._smallValue, Scale, RoundingMode);

                if (diffScale > 0)
                {
                    if (diffScale < _longTenPow.Length && Divisor._bitLength + _longTenPowBitLength[(int)diffScale] < 64)
                        return DividePrimitiveLongs(_smallValue, Divisor._smallValue * _longTenPow[(int)diffScale], Scale, RoundingMode);
                }
                else
                {
                    // diffScale < 0
                    if (-diffScale < _longTenPow.Length && _bitLength + _longTenPowBitLength[(int)-diffScale] < 64)
                        return DividePrimitiveLongs(_smallValue * _longTenPow[(int)-diffScale], Divisor._smallValue, Scale, RoundingMode);
                }
            }

            BigInteger scaledDividend = GetUnscaledValue();
            BigInteger scaledDivisor = Divisor.GetUnscaledValue(); // for scaling of 'u2'

            if (diffScale > 0) // Multiply 'u2'  by:  10^((s1 - s2) - scale)
                scaledDivisor = Multiplication.MultiplyByTenPow(scaledDivisor, (int)diffScale);
            else if (diffScale < 0) // Multiply 'u1'  by:  10^(scale - (s1 - s2))
                scaledDividend = Multiplication.MultiplyByTenPow(scaledDividend, (int)-diffScale);

            return DivideBigIntegers(scaledDividend, scaledDivisor, Scale, RoundingMode);
        }

        /// <summary>
        /// Returns a BigDecimal array which contains the integral part of <c>this / divisor</c> at index 0 and the remainder <c>this % divisor</c> at index 1. 
        /// <para>The quotient is rounded down towards zero to the next integer.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns>
        /// DivideToIntegralValue(Divisor), Remainder(divisor)]
        /// </returns>
        public BigDecimal[] DivideAndRemainder(BigDecimal Divisor)
        {
            BigDecimal[] quotAndRem = new BigDecimal[2];

            quotAndRem[0] = DivideToIntegralValue(Divisor);
            quotAndRem[1] = Subtract(quotAndRem[0].Multiply(Divisor));

            return quotAndRem;
        }

        /// <summary>
        /// Returns a BigDecimal array which contains the integral part of <c>this / divisor</c> at index 0 and the remainder at index 1.
        /// <para>The quotient is rounded down towards zero to the next integer.
        /// The rounding mode passed with the parameter Context is not considered.
        /// But if the precision of Context > 0 and the integral part requires more digits, then an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="Context">Math context which determines the maximal precision of the result</param>
        /// 
        /// <returns>
        /// [DivideToIntegralValue(Divisor), Remainder(Divisor)]
        /// </returns>
        public BigDecimal[] DivideAndRemainder(BigDecimal Divisor, MathContext Context)
        {
            BigDecimal[] quotAndRem = new BigDecimal[2];

            quotAndRem[0] = DivideToIntegralValue(Divisor, Context);
            quotAndRem[1] = Subtract(quotAndRem[0].Multiply(Divisor));

            return quotAndRem;
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is the integral part of <c>this / divisor</c>.
        /// <para>The quotient is rounded down towards zero to the next integer.
        /// For example, <c>0.5/0.2 = 2</c>.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns>
        /// Integral part of <c>this / divisor</c>
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if Divisor == 0</exception>
        public BigDecimal DivideToIntegralValue(BigDecimal Divisor)
        {
            BigInteger integralValue; // the integer of result
            BigInteger powerOfTen; // some power of ten
            BigInteger[] quotAndRem = { GetUnscaledValue() };
            long newScale = (long)_scale - Divisor._scale;
            long tempScale = 0;
            int i = 1;
            int lastPow = _tenPow.Length - 1;

            if (Divisor.IsZero())
                throw new ArithmeticException("Division by zero!");

            if ((Divisor.AproxPrecision() + newScale > AproxPrecision() + 1L) || IsZero())
            {
                // If the divisor's integer part is greater than this's integer part,
                // the result must be zero with the appropriate scale
                integralValue = BigInteger.Zero;
            }
            else if (newScale == 0)
            {
                integralValue = GetUnscaledValue().Divide(Divisor.GetUnscaledValue());
            }
            else if (newScale > 0)
            {
                powerOfTen = Multiplication.PowerOf10(newScale);
                integralValue = GetUnscaledValue().Divide(Divisor.GetUnscaledValue().Multiply(powerOfTen));
                integralValue = integralValue.Multiply(powerOfTen);
            }
            else
            {
                // (newScale < 0)
                powerOfTen = Multiplication.PowerOf10(-newScale);
                integralValue = GetUnscaledValue().Multiply(powerOfTen).Divide(Divisor.GetUnscaledValue());

                // To strip trailing zeros approximating to the preferred scale
                while (!integralValue.TestBit(0))
                {
                    quotAndRem = integralValue.DivideAndRemainder(_tenPow[i]);
                    if ((quotAndRem[1].Signum() == 0) && (tempScale - i >= newScale))
                    {
                        tempScale -= i;
                        if (i < lastPow)
                            i++;

                        integralValue = quotAndRem[0];
                    }
                    else
                    {
                        if (i == 1)
                            break;

                        i = 1;
                    }
                }
                newScale = tempScale;
            }

            return (integralValue.Signum() == 0) ? GetZeroScaledBy(newScale) : new BigDecimal(integralValue, ToIntScale(newScale));
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is the integral part of <c>this / divisor</c>.
        /// <para>The quotient is rounded down towards zero to the next integer.
        /// The rounding mode passed with the parameter Context is not considered.
        /// But if the precision of <c>Context > 0</c> and the integral part requires more digits, 
        /// then an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="Context">Math context which determines the maximal precision of the result</param>
        /// 
        /// <returns>
        /// Integral part of <c>this / divisor</c>
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if quotient won't fit in 'Context.Precision()' digits </exception>
        public BigDecimal DivideToIntegralValue(BigDecimal Divisor, MathContext Context)
        {
            int mcPrecision = Context.Precision;
            int diffPrecision = Precision - Divisor.Precision;
            int lastPow = _tenPow.Length - 1;
            long diffScale = (long)_scale - Divisor._scale;
            long newScale = diffScale;
            long quotPrecision = diffPrecision - diffScale + 1;
            BigInteger[] quotAndRem = new BigInteger[2];

            // In special cases it call the dual method
            if ((mcPrecision == 0) || IsZero() || Divisor.IsZero())
                return DivideToIntegralValue(Divisor);

            // Let be:   this = [u1,s1]   and   divisor = [u2,s2]
            if (quotPrecision <= 0)
            {
                quotAndRem[0] = BigInteger.Zero;
            }
            else if (diffScale == 0)
            {
                // case s1 == s2:  to calculate   u1 / u2 
                quotAndRem[0] = GetUnscaledValue().Divide(Divisor.GetUnscaledValue());
            }
            else if (diffScale > 0)
            {
                // CASE s1 >= s2:  to calculate   u1 / (u2 * 10^(s1-s2)  
                quotAndRem[0] = GetUnscaledValue().Divide(Divisor.GetUnscaledValue().Multiply(Multiplication.PowerOf10(diffScale)));
                // To chose  10^newScale  to get a quotient with at least 'mc.precision()' digits
                newScale = System.Math.Min(diffScale, System.Math.Max(mcPrecision - quotPrecision + 1, 0));
                // To calculate: (u1 / (u2 * 10^(s1-s2)) * 10^newScale
                quotAndRem[0] = quotAndRem[0].Multiply(Multiplication.PowerOf10(newScale));
            }
            else
            {
                // case s2 > s1:   
                /* To calculate the minimum power of ten, such that the quotient 
                 *   (u1 * 10^exp) / u2   has at least 'mc.precision()' digits. */
                long exp = System.Math.Min(-diffScale, System.Math.Max((long)mcPrecision - diffPrecision, 0));
                long compRemDiv;

                // Let be:   (u1 * 10^exp) / u2 = [q,r]  
                quotAndRem = GetUnscaledValue().Multiply(Multiplication.PowerOf10(exp)).DivideAndRemainder(Divisor.GetUnscaledValue());
                newScale += exp; // To fix the scale
                exp = -newScale; // The remaining power of ten

                // If after division there is a remainder...
                if ((quotAndRem[1].Signum() != 0) && (exp > 0))
                {
                    // Log10(r) + ((s2 - s1) - exp) > mc.precision ?
                    compRemDiv = (new BigDecimal(quotAndRem[1])).Precision + exp - Divisor.Precision;
                    if (compRemDiv == 0)
                    {
                        // To calculate:  (r * 10^exp2) / u2
                        quotAndRem[1] = quotAndRem[1].Multiply(Multiplication.PowerOf10(exp)).Divide(Divisor.GetUnscaledValue());
                        compRemDiv = System.Math.Abs(quotAndRem[1].Signum());
                    }

                    // The quotient won't fit in 'mc.precision()' digits
                    if (compRemDiv > 0)
                        throw new ArithmeticException("Division impossible");
                }
            }

            // Fast return if the quotient is zero
            if (quotAndRem[0].Signum() == 0)
                return GetZeroScaledBy(diffScale);

            BigInteger strippedBI = quotAndRem[0];
            BigDecimal integralValue = new BigDecimal(quotAndRem[0]);
            long resultPrecision = integralValue.Precision;
            int i = 1;

            // To strip trailing zeros until the specified precision is reached
            while (!strippedBI.TestBit(0))
            {
                quotAndRem = strippedBI.DivideAndRemainder(_tenPow[i]);
                if ((quotAndRem[1].Signum() == 0) && ((resultPrecision - i >= mcPrecision) || (newScale - i >= diffScale)))
                {
                    resultPrecision -= i;
                    newScale -= i;
                    if (i < lastPow)
                        i++;

                    strippedBI = quotAndRem[0];
                }
                else
                {
                    if (i == 1)
                        break;

                    i = 1;
                }
            }

            // To check if the result fit in 'mc.precision()' digits
            if (resultPrecision > mcPrecision)
                throw new ArithmeticException("Division impossible");

            integralValue._scale = ToIntScale(newScale);
            integralValue.SetUnscaledValue(strippedBI);

            return integralValue;
        }

        /// <summary>
        /// Returns the maximum of this BigDecimal and Value
        /// </summary>
        /// 
        /// <param name="Value">Value to be used to compute the maximum with</param>
        /// 
        /// <returns>
        /// <c>Max(this, Value)</c>
        /// </returns>
        public BigDecimal Max(BigDecimal Value)
        {
            return (CompareTo(Value) >= 0) ? this : Value;
        }

        /// <summary>
        /// Returns the minimum of this BigDecimal and Value
        /// </summary>
        /// 
        /// <param name="Value">Value to be used to compute the minimum with</param>
        /// 
        /// <returns>
        /// <c>Min(this, val)</c>
        /// </returns>
        public BigDecimal Min(BigDecimal Value)
        {
            return (CompareTo(Value) <= 0) ? this : Value;
        }

        /// <summary>
        /// Returns a new BigDecimal instance where the decimal point has been moved N places to the left.
        /// <para>If <c>N &lt; 0</c> then the decimal point is moved -N places to the right.
        /// The result is obtained by changing its scale.
        /// If the scale of the result becomes negative, then its precision is increased such that the scale is zero.
        /// Note, that MovePointLeft(0) returns a result which is mathematically equivalent, but which has scale >= 0.</para>
        /// </summary>
        /// 
        /// <param name="N">Number of places the decimal point has to be moved</param>
        /// 
        /// <returns>
        /// <c>this * 10^(-N)</c>
        /// </returns>
        public BigDecimal MovePointLeft(int N)
        {
            return MovePoint(_scale + (long)N);
        }

        /// <summary>
        /// Returns a new BigDecimal instance where the decimal point has been moved N places to the right. 
        /// <para>If N &lt; 0 then the decimal point is moved -N places to the left.
        /// The result is obtained by changing its scale.
        /// If the scale of the result becomes negative, then its precision is increased such that the scale is zero.
        /// Note, that MovePointRight(0) returns a result which is mathematically equivalent, but which has scale >= 0.</para>
        /// </summary>
        /// 
        /// <param name="N">Number of placed the decimal point has to be moved</param>
        /// 
        /// <returns>
        /// <c>this * 10^n</c>
        /// </returns>
        public BigDecimal MovePointRight(int N)
        {
            return MovePoint(_scale - (long)N);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this * Multiplicand</c>.
        /// <para>The scale of the result is the sum of the scales of the two arguments</para>
        /// </summary>
        /// 
        /// <param name="Multiplicand">Value to be multiplied with this</param>
        /// 
        /// <returns>
        /// <c>this * Multiplicand</c>
        /// </returns>
        public BigDecimal Multiply(BigDecimal Multiplicand)
        {
            long newScale = (long)_scale + Multiplicand._scale;

            if (IsZero() || (Multiplicand.IsZero()))
                return GetZeroScaledBy(newScale);

            // Let be: this = [u1,s1] and multiplicand = [u2,s2] so:
            // this x multiplicand = [ s1 * s2 , s1 + s2 ]
            if (_bitLength + Multiplicand._bitLength < 64)
                return ValueOf(_smallValue * Multiplicand._smallValue, ToIntScale(newScale));

            return new BigDecimal(GetUnscaledValue().Multiply(Multiplicand.GetUnscaledValue()), ToIntScale(newScale));
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this * multiplicand</c>.
        /// <para>The result is rounded according to the passed context.</para>
        /// </summary>
        /// 
        /// <param name="Multiplicand">Value to be multiplied with this</param>
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// <c>this * multiplicand</c>
        /// </returns>
        public BigDecimal Multiply(BigDecimal Multiplicand, MathContext Context)
        {
            BigDecimal result = Multiply(Multiplicand);
            result.InplaceRound(Context);

            return result;
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is the <c>-this</c>.
        /// </summary>
        /// 
        /// <returns>
        /// <c>-this</c>
        /// </returns>
        public BigDecimal Negate()
        {
            if (_bitLength < 63 || (_bitLength == 63 && _smallValue != long.MinValue))
                return ValueOf(-_smallValue, _scale);

            return new BigDecimal(GetUnscaledValue().Negate(), _scale);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is the <c>-this</c>.
        /// </summary>
        /// 
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// The result is <c>-this</c> rounded according to the passed context
        /// </returns>
        public BigDecimal Negate(MathContext Context)
        {
            return Round(Context).Negate();
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>+this</c>.
        /// </summary>
        /// 
        /// <returns>
        /// <c>+this</c>
        /// </returns>
        public BigDecimal Plus()
        {
            return this;
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>+this</c>.
        /// </summary>
        /// 
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// <c>+this</c> rounded according to the passed context 
        /// </returns>
        public BigDecimal Plus(MathContext Context)
        {
            return Round(Context);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this ^ N</c>.
        /// <para>The scale of the result is N times the scales of this.
        /// <c>x.pow(0)</c> returns 1, even if x == 0.</para>
        /// </summary>
        /// 
        /// <param name="N">Exponent to which this is raised</param>
        /// 
        /// <returns>
        /// <c>this ^ N</c>
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if <c>N &lt; 0</c> or <c>N &gt; 999999999</c></exception>
        public BigDecimal Pow(int N)
        {
            if (N == 0)
                return One;

            if ((N < 0) || (N > 999999999))
                throw new ArithmeticException("Invalid Operation");

            long newScale = _scale * (long)N;

            // Let be: this = [u,s]   so:  this^n = [u^n, s*n]
            return (IsZero()) ? GetZeroScaledBy(newScale) : new BigDecimal(GetUnscaledValue().Pow(N), ToIntScale(newScale));
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this ^ N</c>.
        /// <para>The result is rounded according to the passed context.</para>
        /// </summary>
        /// 
        /// <param name="N">Exponent to which this is raised</param>
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// <c>this ^ N</c>
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if <c>N &lt; 0</c> or <c>N &gt; 999999999</c></exception>
        public BigDecimal Pow(int N, MathContext Context)
        {
            // The ANSI standard X3.274-1996 algorithm
            int m = System.Math.Abs(N);
            int mcPrecision = Context.Precision;
            int elength = (int)System.Math.Log10(m) + 1; // decimal digits in 'n'
            int oneBitMask; // mask of bits
            BigDecimal accum; // the single accumulator
            MathContext newPrecision = Context; // MathContext by default

            // In particular cases, it reduces the problem to call the other 'pow()'
            if ((N == 0) || (IsZero() && (N > 0)))
                return Pow(N);

            if ((m > 999999999) || ((mcPrecision == 0) && (N < 0)) || ((mcPrecision > 0) && (elength > mcPrecision)))
                throw new ArithmeticException("Invalid Operation");

            if (mcPrecision > 0)
                newPrecision = new MathContext(mcPrecision + elength + 1, Context.RoundingMode);

            // The result is calculated as if 'n' were positive        
            accum = Round(newPrecision);
            oneBitMask = IntUtils.HighestOneBit(m) >> 1;

            while (oneBitMask > 0)
            {
                accum = accum.Multiply(accum, newPrecision);
                if ((m & oneBitMask) == oneBitMask)
                    accum = accum.Multiply(this, newPrecision);

                oneBitMask >>= 1;
            }

            // If 'n' is negative, the value is divided into 'ONE'
            if (N < 0)
                accum = One.Divide(accum, newPrecision);

            // The  value is rounded to the destination precision
            accum.InplaceRound(Context);

            return accum;
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this % divisor</c>.
        /// <para>The remainder is defined as <c>this - DivideToIntegralValue(Divisor) * Divisor</c>.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// 
        /// <returns>
        /// <c>this % divisor</c>
        /// </returns>
        public BigDecimal Remainder(BigDecimal Divisor)
        {
            return DivideAndRemainder(Divisor)[1];
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this % divisor</c>.
        /// <para>The remainder is defined as <c>this - DivideToIntegralValue(Divisor) * Divisor</c>.
        /// The specified rounding mode Context is used for the division only.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">Value by which this is divided</param>
        /// <param name="Context">Rounding mode and precision to be used</param>
        /// 
        /// <returns>
        /// <c>this % divisor</c>
        /// </returns>
        public BigDecimal Remainder(BigDecimal Divisor, MathContext Context)
        {
            return DivideAndRemainder(Divisor, Context)[1];
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is this, rounded according to the passed context.
        /// <para>If Context.Precision = 0, then no rounding is performed.
        /// If Context.Precision and Context.RoundingMode == UNNECESSARY, then an ArithmeticException 
        /// is thrown if the result cannot be represented exactly within the given precision.</para>
        /// </summary>
        /// 
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// This rounded according to the passed context
        /// </returns>
        public BigDecimal Round(MathContext Context)
        {
            BigDecimal thisBD = new BigDecimal(GetUnscaledValue(), _scale);
            thisBD.InplaceRound(Context);

            return thisBD;
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this 10^ N</c>.
        /// <para>The scale of the result is Scale() - N.
        /// The precision of the result is the precision of this.
        /// This method has the same effect as MovePointRight, except that the precision is not changed.</para>
        /// </summary>
        /// 
        /// <param name="N">Number of places the decimal point has to be moved</param>
        /// 
        /// <returns>
        /// <c>this 10^ N</c>
        /// </returns>
        public BigDecimal ScaleByPowerOfTen(int N)
        {
            long newScale = _scale - (long)N;
            if (_bitLength < 64)
            {
                // Taking care when a 0 is to be scaled
                if (_smallValue == 0)
                    return GetZeroScaledBy(newScale);

                return ValueOf(_smallValue, ToIntScale(newScale));
            }

            return new BigDecimal(GetUnscaledValue(), ToIntScale(newScale));
        }

        /// <summary>
        /// Returns a new BigDecimal instance with the specified scale.
        /// <para>If the new scale is greater than the old scale, then additional zeros are added to the unscaled value.
        /// If the new scale is smaller than the old scale, then trailing zeros are removed.
        /// If the trailing digits are not zeros then an ArithmeticException is thrown.
        /// If no exception is thrown, then the following equation holds: <c>x.SetScale(s).CompareTo(x) == 0</c>.</para>
        /// </summary>
        /// 
        /// <param name="NewScale">Scale of the result returned</param>
        /// 
        /// <returns>
        /// A new BigDecimal instance with the specified scale.
        /// </returns>
        public BigDecimal SetScale(int NewScale)
        {
            return SetScale(NewScale, RoundingModes.Unnecessary);
        }

        /// <summary>
        /// Returns a new BigDecimal instance with the specified scale.
        /// <para>If the new scale is greater than the old scale, then additional zeros are added to the unscaled value.
        /// If the new scale is smaller than the old scale, then trailing digits are removed.
        /// In this case no rounding is necessary.
        /// If these trailing digits are not zero, then the remaining unscaled value has to be rounded.
        /// For this rounding operation the specified rounding mode is used.</para>
        /// </summary>
        /// 
        /// <param name="NewScale">Scale of the result returned</param>
        /// <param name="RoundingMode">Rounding mode to be used to round the result</param>
        /// 
        /// <returns>
        /// A new BigDecimal instance with the specified scale
        /// </returns>
        public BigDecimal SetScale(int NewScale, RoundingModes RoundingMode)
        {
            long diffScale = NewScale - (long)_scale;

            // Let be:  'this' = [u,s]        
            if (diffScale == 0)
                return this;

            if (diffScale > 0)
            {
                // return  [u * 10^(s2 - s), newScale]
                if (diffScale < _longTenPow.Length && (_bitLength + _longTenPowBitLength[(int)diffScale]) < 64)
                    return ValueOf(_smallValue * _longTenPow[(int)diffScale], NewScale);

                return new BigDecimal(Multiplication.MultiplyByTenPow(GetUnscaledValue(), (int)diffScale), NewScale);
            }

            // diffScale < 0
            // return  [u,s] / [1,newScale]  with the appropriate scale and rounding
            if (_bitLength < 64 && -diffScale < _longTenPow.Length)
                return DividePrimitiveLongs(_smallValue, _longTenPow[(int)-diffScale], NewScale, RoundingMode);

            return DivideBigIntegers(GetUnscaledValue(), Multiplication.PowerOf10(-diffScale), NewScale, RoundingMode);
        }

        /// <summary>
        /// Returns a new BigDecimal instance with the specified scale.
        /// <para>If the new scale is greater than the old scale, then additional zeros are added to the unscaled value.
        /// In this case no rounding is necessary.
        /// If the new scale is smaller than the old scale, then trailing digits are removed.
        /// If these trailing digits are not zero, then the remaining unscaled value has to be rounded.
        /// For this rounding operation the specified rounding mode is used.</para>
        /// </summary>
        /// 
        /// <param name="NewScale">Scale of the result returned</param>
        /// <param name="RoundMode">Rounding mode to be used to round the result</param>
        /// 
        /// <returns>
        /// A new BigDecimal instance with the specified scale
        /// </returns>
        /// 
        /// <exception cref="ArgumentException">Thrown if RoundMode is not a valid rounding mode</exception>
        public BigDecimal SetScale(int NewScale, int RoundMode)
        {
            RoundingModes rm = (RoundingModes)RoundMode;

            if ((RoundMode < (int)RoundingModes.Up) || (RoundMode > (int)RoundingModes.Unnecessary))
                throw new ArgumentException("roundingMode");

            return SetScale(NewScale, (RoundingModes)RoundMode);
        }

        /// <summary>
        /// Returns the sign of this BigDecimal
        /// </summary>
        /// 
        /// <returns>
        /// Returns <c>-1</c> if <c>this &lt; 0</c>, <c>0</c> if <c>this == 0</c>, <c>1</c> if <c>this &gt; 0</c>
        /// </returns>
        public int Signum()
        {
            if (_bitLength < 64)
                return System.Math.Sign(_smallValue);

            return GetUnscaledValue().Signum();
        }

        /// <summary>
        /// Returns a new BigDecimal instance with the same value as this but with a 
        /// unscaled value where the trailing zeros have been removed.
        /// <para>If the unscaled value of this has n trailing zeros, 
        /// then the scale and the precision of the result has been reduced by n.
        /// </para>
        /// </summary>
        /// 
        /// <returns>
        /// A new BigDecimal instance equivalent to this where the trailing zeros of the unscaled value have been removed
        /// </returns>
        public BigDecimal StripTrailingZeros()
        {
            int i = 1; // 1 <= i <= 18
            int lastPow = _tenPow.Length - 1;
            long newScale = _scale;

            if (IsZero())
                return new BigDecimal("0");

            BigInteger strippedBI = GetUnscaledValue();
            BigInteger[] quotAndRem;

            // while the number is even...
            while (!strippedBI.TestBit(0))
            {
                // To divide by 10^i
                quotAndRem = strippedBI.DivideAndRemainder(_tenPow[i]);

                // To look the remainder
                if (quotAndRem[1].Signum() == 0)
                {
                    // To adjust the scale
                    newScale -= i;
                    // To set to the next power
                    if (i < lastPow)
                        i++;

                    strippedBI = quotAndRem[0];
                }
                else
                {
                    // 'this' has no more trailing zeros
                    if (i == 1)
                        break;

                    // To set to the smallest power of ten
                    i = 1;
                }
            }

            return new BigDecimal(strippedBI, ToIntScale(newScale));
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this - subtrahend</c>.
        /// <para>The scale of the result is the maximum of the scales of the two arguments.</para>
        /// </summary>
        /// 
        /// <param name="Subtrahend">Value to be subtracted from this</param>
        /// 
        /// <returns>
        /// <c>this - subtrahend</c>
        /// </returns>
        public BigDecimal Subtract(BigDecimal Subtrahend)
        {
            int diffScale = _scale - Subtrahend._scale;

            // Fast return when some operand is zero
            if (IsZero())
            {
                if (diffScale <= 0)
                    return Subtrahend.Negate();
                if (Subtrahend.IsZero())
                    return this;
            }
            else if (Subtrahend.IsZero())
            {
                if (diffScale >= 0)
                    return this;
            }

            // Let be: this = [u1,s1] and subtrahend = [u2,s2] so:
            if (diffScale == 0)
            {
                // case s1 = s2 : [u1 - u2 , s1]
                if (System.Math.Max(_bitLength, Subtrahend._bitLength) + 1 < 64)
                    return ValueOf(_smallValue - Subtrahend._smallValue, _scale);

                return new BigDecimal(GetUnscaledValue().Subtract(Subtrahend.GetUnscaledValue()), _scale);
            }

            if (diffScale > 0)
            {
                // case s1 > s2 : [ u1 - u2 * 10 ^ (s1 - s2) , s1 ]
                if (diffScale < _longTenPow.Length && System.Math.Max(_bitLength, Subtrahend._bitLength + _longTenPowBitLength[diffScale]) + 1 < 64)
                    return ValueOf(_smallValue - Subtrahend._smallValue * _longTenPow[diffScale], _scale);

                return new BigDecimal(GetUnscaledValue().Subtract(Multiplication.MultiplyByTenPow(Subtrahend.GetUnscaledValue(), diffScale)), _scale);
            }

            // case s2 > s1 : [ u1 * 10 ^ (s2 - s1) - u2 , s2 ]
            diffScale = -diffScale;
            if (diffScale < _longTenPow.Length && System.Math.Max(_bitLength + _longTenPowBitLength[diffScale], Subtrahend._bitLength) + 1 < 64)
                return ValueOf(_smallValue * _longTenPow[diffScale] - Subtrahend._smallValue, Subtrahend._scale);

            return new BigDecimal(Multiplication.MultiplyByTenPow(GetUnscaledValue(), diffScale).Subtract(Subtrahend.GetUnscaledValue()), Subtrahend._scale);
        }

        /// <summary>
        /// Returns a new BigDecimal}whose value is <c>this - subtrahend</c>.
        /// <para>The scale of the result is the maximum of the scales of the two arguments.</para>
        /// </summary>
        /// 
        /// <param name="Subtrahend">Value to be subtracted from this</param>
        /// <param name="Context">Rounding mode and precision for the result of this operation</param>
        /// 
        /// <returns>
        /// <c>this - subtrahend</c>
        /// </returns>
        public BigDecimal Subtract(BigDecimal Subtrahend, MathContext Context)
        {
            long diffScale = Subtrahend._scale - (long)_scale;
            int thisSignum;
            BigDecimal leftOperand; // it will be only the left operand (this) 
            BigInteger tempBI;

            // Some operand is zero or the precision is infinity  
            if (Subtrahend.IsZero() || (IsZero()) || (Context.Precision == 0))
                return Subtract(Subtrahend).Round(Context);

            // Now:   this != 0   and   subtrahend != 0
            if (Subtrahend.AproxPrecision() < diffScale - 1)
            {
                // Cases where it is unnecessary to subtract two numbers with very different scales
                if (Context.Precision < AproxPrecision())
                {
                    thisSignum = Signum();
                    if (thisSignum != Subtrahend.Signum())
                    {
                        tempBI = Multiplication.MultiplyByPositiveInt(GetUnscaledValue(), 10).Add(BigInteger.ValueOf(thisSignum));
                    }
                    else
                    {
                        tempBI = GetUnscaledValue().Subtract(BigInteger.ValueOf(thisSignum));
                        tempBI = Multiplication.MultiplyByPositiveInt(tempBI, 10).Add(BigInteger.ValueOf(thisSignum * 9));
                    }

                    // Rounding the improved subtracting
                    leftOperand = new BigDecimal(tempBI, _scale + 1);
                    return leftOperand.Round(Context);
                }
            }

            // No optimization is done
            return Subtract(Subtrahend).Round(Context);
        }

        /// <summary>
        /// Returns this BigDecimal as a big integer instance.
        /// <para>A fractional part is discarded.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as a big integer instance
        /// </returns>
        public BigInteger ToBigInteger()
        {
            if ((_scale == 0) || IsZero())
                return GetUnscaledValue();
            else if (_scale < 0)
                return GetUnscaledValue().Multiply(Multiplication.PowerOf10(-(long)_scale));
            else // (scale > 0)
                return GetUnscaledValue().Divide(Multiplication.PowerOf10(_scale));
        }

        /// <summary>
        /// Returns this BigDecimal as a big integer instance if it has no fractional part.
        /// <para>If this BigDecimal has a fractional part, i.e. if rounding would be necessary, an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <returns>
        /// this BigDecimal as a big integer value
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if rounding is necessary</exception>
        public BigInteger ToBigIntegerExact()
        {
            if ((_scale == 0) || IsZero())
            {
                return GetUnscaledValue();
            }
            else if (_scale < 0)
            {
                return GetUnscaledValue().Multiply(Multiplication.PowerOf10(-(long)_scale));
            }
            else
            {
                // (scale > 0)
                BigInteger[] integerAndFraction;

                // An optimization before do a heavy division
                if ((_scale > AproxPrecision()) || (_scale > GetUnscaledValue().LowestSetBit))
                    throw new ArithmeticException("Rounding necessary");

                integerAndFraction = GetUnscaledValue().DivideAndRemainder(Multiplication.PowerOf10(_scale));

                // It exists a non-zero fractional part 
                if (integerAndFraction[1].Signum() != 0)
                    throw new ArithmeticException("Rounding necessary");

                return integerAndFraction[0];
            }
        }

        /// <summary>
        /// Returns this BigDecimal as a byte value if it has no fractional part and 
        /// if its value fits to the byte range ([-128..127]).
        /// <para>If these conditions are not met, an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as a byte value
        /// </returns>
        public byte ToByteExact()
        {
            return (byte)ValueExact(8);
        }

        /// <summary>
        /// Returns this BigDecimal as a double value.
        /// <para>If this is too big to be represented as an float, then Double.POSITIVE_INFINITY or Double.NEGATIVE_INFINITY is returned.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as a double value
        /// </returns>
        /// 
        /// <remarks>
        /// <para>Note, that if the unscaled value has more than 53 significant digits, 
        /// then this decimal cannot be represented exactly in a double variable.
        /// In this case the result is rounded.
        /// For example, if the instance <c>x1 = new BigDecimal("0.1")</c> cannot be 
        /// represented exactly as a double, and thus <c>x1.Equals(new BigDecimal(x1.ToDouble())</c> 
        /// returns false for this case.
        /// Similarly, if the instance <c>new BigDecimal(9007199254740993L)</c>c> is converted to a double, 
        /// the result is 9.007199254740992E15.</para>
        /// </remarks>
        public double ToDouble()
        {
            int sign = Signum();
            int exponent = 1076; // bias + 53
            int lowestSetBit;
            int discardedSize;
            long powerOfTwo = _bitLength - (long)(_scale / LOG10_2);
            long bits; // IEEE-754 Standard
            long tempBits; // for temporal calculations     
            BigInteger mantisa;

            // Cases which 'this' is very small        
            if ((powerOfTwo < -1074) || (sign == 0))
                return sign * 0.0d;
            // Cases which 'this' is very large   
            else if (powerOfTwo > 1025)
                return sign * double.PositiveInfinity;

            mantisa = GetUnscaledValue().Abs();

            // Let be:  this = [u,s], with s > 0
            if (_scale <= 0)
            {
                // mantisa = abs(u) * 10^s
                mantisa = mantisa.Multiply(Multiplication.PowerOf10(-_scale));
            }
            else
            {
                // (scale > 0)
                BigInteger[] quotAndRem;
                BigInteger powerOfTen = Multiplication.PowerOf10(_scale);
                int k = 100 - (int)powerOfTwo;
                int compRem;

                if (k > 0)
                {
                    // Computing (mantisa * 2^k) , where 'k' is a enough big
                    // power of '2' to can divide by 10^s
                    mantisa = mantisa.ShiftLeft(k);
                    exponent -= k;
                }

                // Computing (mantisa * 2^k) / 10^s
                quotAndRem = mantisa.DivideAndRemainder(powerOfTen);
                // To check if the fractional part >= 0.5
                compRem = quotAndRem[1].ShiftLeftOneBit().CompareTo(powerOfTen);
                // To add two rounded bits at end of mantisa
                mantisa = quotAndRem[0].ShiftLeft(2).Add(BigInteger.ValueOf((compRem * (compRem + 3)) / 2 + 1));
                exponent -= 2;
            }

            lowestSetBit = mantisa.LowestSetBit;
            discardedSize = mantisa.BitLength - 54;
            if (discardedSize > 0)
            {
                // (n > 54)
                // mantisa = (abs(u) * 10^s) >> (n - 54)
                bits = mantisa.ShiftRight(discardedSize).ToInt64();
                tempBits = bits;

                // #bits = 54, to check if the discarded fraction produces a carry             
                if ((((bits & 1) == 1) && (lowestSetBit < discardedSize)) || ((bits & 3) == 3))
                    bits += 2;
            }
            else
            {
                // (n <= 54)
                // mantisa = (abs(u) * 10^s) << (54 - n)                
                bits = mantisa.ToInt64() << -discardedSize;
                tempBits = bits;

                // #bits = 54, to check if the discarded fraction produces a carry:
                if ((bits & 3) == 3)
                    bits += 2;
            }

            // Testing bit 54 to check if the carry creates a new binary digit
            if ((bits & 0x40000000000000L) == 0)
            {
                // To drop the last bit of mantisa (first discarded)
                bits >>= 1;
                // exponent = 2^(s-n+53+bias)
                exponent += discardedSize;
            }
            else
            {
                // #bits = 54
                bits >>= 2;
                exponent += discardedSize + 1;
            }

            // To test if the 53-bits number fits in 'double'            
            if (exponent > 2046)
            {
                // (exponent - bias > 1023)
                return sign * double.PositiveInfinity;
            }

            if (exponent <= 0)
            {
                // (exponent - bias <= -1023)
                // Denormalized numbers (having exponent == 0)
                if (exponent < -53)
                {
                    // exponent - bias < -1076
                    return sign * 0.0d;
                }

                // -1076 <= exponent - bias <= -1023 
                // To discard '- exponent + 1' bits
                bits = tempBits >> 1;
                tempBits = bits & IntUtils.URShift(-1L, 63 + exponent);
                bits >>= -exponent;

                // To test if after discard bits, a new carry is generated
                if (((bits & 3) == 3) || (((bits & 1) == 1) && (tempBits != 0) && (lowestSetBit < discardedSize)))
                {
                    bits += 1;
                }

                exponent = 0;
                bits >>= 1;
            }

            // Construct the 64 double bits: [sign(1), exponent(11), mantisa(52)]
            // bits = (long)((ulong)sign & 0x8000000000000000L) | ((long)exponent << 52) | (bits & 0xFFFFFFFFFFFFFL);
            bits = sign & long.MinValue | ((long)exponent << 52) | (bits & 0xFFFFFFFFFFFFFL);
            return BitConverter.Int64BitsToDouble(bits);
        }

        /// <summary>
        /// Returns a string representation of this BigDecimal.
        /// <para>This representation always prints all significant digits of this value.
        /// If the scale is negative or if Scale - Precision >= 6 then engineering notation is used.
        /// Engineering notation is similar to the scientific notation except that the exponent is made to be a multiple of 3 such that the integer part is >= 1 and &lt; 1000.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns a string representation of this in engineering notation if necessary
        /// </returns>
        public string ToEngineeringString()
        {
            string intString = GetUnscaledValue().ToString();
            if (_scale == 0)
            {
                return intString;
            }

            int begin = (GetUnscaledValue().Signum() < 0) ? 2 : 1;
            int end = intString.Length;
            long exponent = -(long)_scale + end - begin;
            StringBuilder result = new StringBuilder(intString);

            if ((_scale > 0) && (exponent >= -6))
            {
                if (exponent >= 0)
                {
                    result.Insert(end - _scale, '.');
                }
                else
                {
                    result.Insert(begin - 1, "0."); // $NON-NLS-1$
                    result.Insert(begin + 1, _chZeros, 0, -(int)exponent - 1);
                }
            }
            else
            {
                int delta = end - begin;
                int rem = (int)(exponent % 3);

                if (rem != 0)
                {
                    // adjust exponent so it is a multiple of three
                    if (GetUnscaledValue().Signum() == 0)
                    {
                        // zero value
                        rem = (rem < 0) ? -rem : 3 - rem;
                        exponent += rem;
                    }
                    else
                    {
                        // nonzero value
                        rem = (rem < 0) ? rem + 3 : rem;
                        exponent -= rem;
                        begin += rem;
                    }

                    if (delta < 3)
                    {
                        for (int i = rem - delta; i > 0; i--)
                        {
                            result.Insert(end++, '0');
                        }
                    }
                }

                if (end - begin >= 1)
                {
                    result.Insert(begin, '.');
                    end++;
                }

                if (exponent != 0)
                {
                    result.Insert(end, 'E');
                    if (exponent > 0)
                    {
                        result.Insert(++end, '+');
                    }

                    result.Insert(++end, Convert.ToString(exponent));
                }
            }

            return result.ToString();
        }

        /// <summary>
        /// Returns this BigDecimal as a short value if it has no fractional part 
        /// and if its value fits to the short range ([-2^{15}..2^{15}-1]).
        /// <para>If these conditions are not met, an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as a short value
        /// </returns>
        public short ToInt16Exact()
        {
            return (short)ValueExact(16);
        }

        /// <summary>
        /// Returns this BigDecimal as an int value.
        /// <para>If the integral part of this is too big to be represented as an int, then this % 2^32 is returned.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as an int value
        /// </returns>
        public int ToInt32()
        {
            // If scale <= -32 there are at least 32 trailing bits zero in 10^(-scale).
            // If the scale is positive and very large the long value could be zero.
            return (_scale <= -32) || (_scale > AproxPrecision()) ? 0 : ToBigInteger().ToInt32();
        }

        /// <summary>
        /// Returns this BigDecimal as an int value. Any fractional part is discarded.
        /// <para>Returns this BigDecimal as a int value if it has no fractional part and if 
        /// its value fits to the int range ([-2^{31}..2^{31}-1]).
        /// If these conditions are not met, an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <returns>
        /// This BigDecimal as a int value
        /// </returns>
        public int ToInt32Exact()
        {
            return (int)ValueExact(32);
        }

        /// <summary>
        /// Returns this BigDecimal as an long value. Any fractional part is discarded.
        /// <para>If the integral part of this is too big to be represented as an long, then this % 2^64 is returned.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as a long value
        /// </returns>
        public long ToInt64()
        {
            // If scale <= -64 there are at least 64 trailing bits zero in 10^(-scale).
            // If the scale is positive and very large the long value could be zero.
            return (_scale <= -64) || (_scale > AproxPrecision()) ? 0L : ToBigInteger().ToInt64();
        }

        /// <summary>
        /// Returns this BigDecimal as a long value if it has no fractional part and if its value fits to the int range ([-2^{63}..2^{63}-1]).
        /// <para>If these conditions are not met, an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <returns>
        /// this BigDecimal as a long value
        /// </returns>
        public long ToInt64Exact()
        {
            return ValueExact(64);
        }

        /// <summary>
        /// Returns a string representation of this BigDecimal.
        /// <para>No scientifi notation is used. This methods adds zeros where necessary.
        /// If this string representation is used to create a new instance, 
        /// this instance is generally not identical to this as the precision changes.
        /// <c>x.Equals(new BigDecimal(x.ToPlainString())</c> usually returns false.
        /// <c>x.CompareTo(new BigDecimal(x.ToPlainString())} returns 0</c></para>
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of this without exponent part.
        /// </returns>
        public string ToPlainString()
        {
            string intStr = GetUnscaledValue().ToString();
            if ((_scale == 0) || (IsZero() && (_scale < 0)))
            {
                return intStr;
            }

            int begin = (Signum() < 0) ? 1 : 0;
            int delta = _scale;

            // We take space for all digits, plus a possible decimal point, plus 'scale'
            StringBuilder result = new StringBuilder(intStr.Length + 1 + System.Math.Abs(_scale));

            if (begin == 1)
            {
                // If the number is negative, we insert a '-' CharHelper at front 
                result.Append('-');
            }

            if (_scale > 0)
            {
                delta -= intStr.Length - begin;
                if (delta >= 0)
                {
                    result.Append("0."); // $NON-NLS-1$

                    // To append zeros after the decimal point
                    for (; delta > _chZeros.Length; delta -= _chZeros.Length)
                    {
                        result.Append(_chZeros);
                    }

                    result.Append(_chZeros, 0, delta);
                    result.Append(intStr.Substring(begin));
                }
                else
                {
                    delta = begin - delta;
                    result.Append(intStr.Substring(begin, delta - begin));
                    result.Append('.');
                    result.Append(intStr.Substring(delta));
                }
            }
            else
            {
                // (scale <= 0)
                result.Append(intStr.Substring(begin));

                // To append trailing zeros
                for (; delta < -_chZeros.Length; delta += _chZeros.Length)
                {
                    result.Append(_chZeros);
                }

                result.Append(_chZeros, 0, -delta);
            }

            return result.ToString();
        }

        /// <summary>
        /// Returns this BigDecimal as a float value.
        /// <para>If this is too big to be represented as an float, 
        /// then Float.POSITIVE_INFINITY or Float.NEGATIVE_INFINITY is returned.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns this BigDecimal as a float value
        /// </returns>
        /// 
        /// <remarks>
        /// <para>Note, that if the unscaled value has more than 24 significant digits, 
        /// then this decimal cannot be represented exactly in a float variable.
        /// In this case the result is rounded.
        /// For example, if the instance <c>x1 = new BigDecimal("0.1")</c> cannot be represented exactly as a float, 
        /// and thus <c>x1.Equals(new BigDecimal(x1.FloatValue())</c> returns false for this case.
        /// Similarly, if the instance <c>new BigDecimal(16777217)</c> is converted to a float, the result is 1.6777216E7.</para>
        /// </remarks>
        public float ToSingle()
        {
            /* A similar code like in ToDouble() could be repeated here,
             * but this simple implementation is quite efficient. */
            float floatResult = Signum();
            long powerOfTwo = _bitLength - (long)(_scale / LOG10_2);
            if ((powerOfTwo < -149) || (floatResult == 0.0f))
            {
                // Cases which 'this' is very small
                floatResult *= 0.0f;
            }
            else if (powerOfTwo > 129)
            {
                // Cases which 'this' is very large
                floatResult *= float.PositiveInfinity;
            }
            else
            {
                floatResult = (float)ToDouble();
            }

            return floatResult;
        }

        /// <summary>
        /// Returns the unit in the last place (ULP) of this BigDecimal instance.
        /// <para>An ULP is the distance to the nearest big decimal with the same precision.</para>para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns unit in the last place (ULP) of this BigDecimal instance
        /// </returns>
        /// 
        /// <remarks>
        /// <para>The amount of a rounding error in the evaluation of a floating-point operation is 
        /// often expressed in ULPs. An error of 1 ULP is often seen as a tolerable error.
        /// For class BigDecimal, the ULP of a number is simply 10^(-scale).
        /// For example, {@code new BigDecimal(0.1).ulp()} returns {@code 1E-55}.</para>
        /// </remarks>
        public BigDecimal Ulp()
        {
            return ValueOf(1, _scale);
        }

        /// <summary>
        /// Returns a new BigDecimal instance whose value is equal to value.
        /// <para>The new decimal is constructed as if the BigDecimal(String) constructor is called
        /// with an argument which is equal to Double.toString(val). 
        /// For example, ValueOf("0.1")} is converted to (unscaled=1, scale=1), although the double 0.1 cannot be
        /// represented exactly as a double value. In contrast to that, a new BigDecimal(0.1) instance has the value 
        /// 0.1000000000000000055511151231257827021181583404541015625 with an unscaled value 
        /// 1000000000000000055511151231257827021181583404541015625}and the scale 55.</para>
        /// </summary>
        /// 
        /// <param name="Value">Double value to be converted to a {@code BigDecimal</param>
        /// 
        /// <returns>
        /// BigDecimal instance with the value 
        /// </returns>
        /// 
        /// <exception cref="FormatException">Thrown if Value is infinite or not a number</exception>
        public static BigDecimal ValueOf(double Value)
        {
            if (double.IsInfinity(Value) || double.IsNaN(Value))
                throw new FormatException("Infinity or NaN");

            return new BigDecimal(Convert.ToString(Value, CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Returns a new <see cref="BigDecimal"/> instance whose value is equal to <paramref name="UnscaledVal"/>. 
        /// <para>The scale of the result is <c>0</c>, and its unscaled value is <paramref name="UnscaledVal"/>.</para>
        /// </summary>
        /// 
        /// <param name="UnscaledVal">The value to be converted to a <see cref="BigDecimal"/></param>
        /// <returns>
        /// Returns a <see cref="BigDecimal"/> instance with the value <paramref name="UnscaledVal"/>.
        /// </returns>
        public static BigDecimal ValueOf(long UnscaledVal)
        {
            if ((UnscaledVal >= 0) && (UnscaledVal < BISCALEDZERO_LEN))
                return _biScaledByZero[(int)UnscaledVal];

            return new BigDecimal(UnscaledVal, 0);
        }

        /// <summary>
        /// Returns a new <see cref="BigDecimal"/> instance whose value is equal to 
        /// <paramref name="UnscaledVal"/> 10^(-<paramref name="Scale"/>). 
        /// <para>The scale of the result is <see cref="Scale"/>, and its unscaled value is <see cref="UnScaledValue"/>.</para>
        /// </summary>
        /// 
        /// <param name="UnscaledVal">The unscaled value to be used to construct the new <see cref="BigDecimal"/></param>
        /// <param name="Scale">The scale to be used to construct the new <see cref="BigDecimal"/>.</param>
        /// 
        /// <returns>
        /// Returns a <see cref="BigDecimal"/> instance with the value <c>UnscaledVal * 10^(-scale)</c>.
        /// </returns>
        public static BigDecimal ValueOf(long UnscaledVal, int Scale)
        {
            if (Scale == 0)
                return ValueOf(UnscaledVal);

            if ((UnscaledVal == 0) && (Scale >= 0) && (Scale < _zeroScaledBy.Length))
                return _zeroScaledBy[Scale];

            return new BigDecimal(UnscaledVal, Scale);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// If the precision already was calculated it returns that value, otherwise it calculates a very good approximation efficiently .
        /// </summary>
        /// 
        /// <returns>
        /// Returns an approximation of Precision() value
        /// </returns>
        private int AproxPrecision()
        {
            return ((_precision > 0) ? _precision : (int)((_bitLength - 1) * LOG10_2)) + 1;
        }

        /// <summary>
        /// The bit length
        /// </summary>
        /// 
        /// <param name="SmallValue"> The small value</param>
        /// 
        /// <returns>
        /// The <see cref="int"/>.
        /// </returns>
        private static int BitLength(long SmallValue)
        {
            if (SmallValue < 0)
                SmallValue = ~SmallValue;

            return 64 - IntUtils.NumberOfLeadingZeros(SmallValue);
        }

        /// <summary>
        /// The bit length
        /// </summary>
        /// 
        /// <param name="SmallValue">The small value</param>
        /// 
        /// <returns>
        /// The <see cref="int"/>.
        /// </returns>
        private static int BitLength(int SmallValue)
        {
            if (SmallValue < 0)
                SmallValue = ~SmallValue;

            return 32 - IntUtils.NumberOfLeadingZeros(SmallValue);
        }

        /// <summary>
        /// Divide big integers
        /// </summary>
        /// <param name="ScaledDividend">The scaled dividend</param>
        /// <param name="ScaledDivisor">The scaled divisor</param>
        /// <param name="Scale">The scale</param>
        /// <param name="RoundingMode">The rounding mode</param>
        /// 
        /// <returns>
        /// The <see cref="BigDecimal"/> remainder
        /// </returns>
        private static BigDecimal DivideBigIntegers(BigInteger ScaledDividend, BigInteger ScaledDivisor, int Scale, RoundingModes RoundingMode)
        {
            BigInteger[] quotAndRem = ScaledDividend.DivideAndRemainder(ScaledDivisor); // quotient and remainder

            // If after division there is a remainder...
            BigInteger quotient = quotAndRem[0];
            BigInteger remainder = quotAndRem[1];

            if (remainder.Signum() == 0)
                return new BigDecimal(quotient, Scale);

            int sign = ScaledDividend.Signum() * ScaledDivisor.Signum();
            int compRem; // 'compare to remainder'
            if (ScaledDivisor.BitLength < 63)
            {
                // 63 in order to avoid out of long after <<1
                long rem = remainder.ToInt64();
                long divisor = ScaledDivisor.ToInt64();
                compRem = LongCompareTo(System.Math.Abs(rem) << 1, System.Math.Abs(divisor));
                // To look if there is a carry
                compRem = RoundingBehavior(quotient.TestBit(0) ? 1 : 0, sign * (5 + compRem), RoundingMode);
            }
            else
            {
                // Checking if:  remainder * 2 >= scaledDivisor 
                compRem = remainder.Abs().ShiftLeftOneBit().CompareTo(ScaledDivisor.Abs());
                compRem = RoundingBehavior(quotient.TestBit(0) ? 1 : 0, sign * (5 + compRem), RoundingMode);
            }

            if (compRem != 0)
            {
                if (quotient.BitLength < 63)
                    return ValueOf(quotient.ToInt64() + compRem, Scale);

                quotient = quotient.Add(BigInteger.ValueOf(compRem));
                return new BigDecimal(quotient, Scale);
            }

            // Constructing the result with the appropriate unscaled value
            return new BigDecimal(quotient, Scale);
        }

        /// <summary>
        /// Divide primitive longs
        /// </summary>
        /// 
        /// <param name="ScaledDividend">The scaled dividend</param>
        /// <param name="ScaledDivisor">The scaled divisor</param>
        /// <param name="Scale">The scale</param>
        /// <param name="RoundingMode">The rounding mode</param>
        /// 
        /// <returns>
        /// The <see cref="BigDecimal"/>
        /// </returns>
        private static BigDecimal DividePrimitiveLongs(long ScaledDividend, long ScaledDivisor, int Scale, RoundingModes RoundingMode)
        {
            long quotient = ScaledDividend / ScaledDivisor;
            long remainder = ScaledDividend % ScaledDivisor;
            int sign = System.Math.Sign(ScaledDividend) * System.Math.Sign(ScaledDivisor);

            if (remainder != 0)
            {
                // Checking if:  remainder * 2 >= scaledDivisor
                int compRem; // 'compare to remainder'
                compRem = LongCompareTo(System.Math.Abs(remainder) << 1, System.Math.Abs(ScaledDivisor));
                // To look if there is a carry
                quotient += RoundingBehavior(((int)quotient) & 1, sign * (5 + compRem), RoundingMode);
            }

            // Constructing the result with the appropriate unscaled value
            return ValueOf(quotient, Scale);
        }

        /// <summary>
        /// Convert a double to long
        /// </summary>
        /// 
        /// <param name="Value">The value to convert</param>
        /// 
        /// <returns>
        /// The long integer value
        /// </returns>
        private static long DoubleToLongBits(double Value)
        {
            long num;
            long num4;

            if (IsNaN(Value))
                return 0x7ff8000000000000L;

            if (Value == double.PositiveInfinity)
                return 0x7ff0000000000000L;

            if (Value == double.NegativeInfinity)
                return -4503599627370496L;

            if (Value == 0.0)
            {
                if (IsNegativeZero(Value))
                    return -9223372036854775808L;

                return 0L;
            }

            if (Value > 0.0)
            {
                num = 0L;
            }
            else
            {
                num = -9223372036854775808L;
                Value = -Value;
            }

            double num2 = Value;
            long num3 = 0L;
            while (Value >= 2.0)
            {
                Value /= 2.0;
                num3 += 1L;
            }

            while (Value < 1.0)
            {
                Value *= 2.0;
                num3 += -1L;
            }

            num3 += 0x3ffL;
            if (num3 < 0L)
                num3 = 0L;

            num3 = num3 << 0x34;
            if (num2 <= System.Math.Pow(2.0, -1022.0))
            {
                for (int i = 0; i < 0x432; i++)
                    num2 *= 2.0;

                num4 = IntUtils.DoubleToLong(num2);
            }
            else
            {
                num4 = 0xfffffffffffffL & IntUtils.DoubleToLong(Value * System.Math.Pow(2.0, 52.0));
            }

            return (num | num3) | num4;
        }

        /// <summary>
        /// The get unscaled value
        /// </summary>
        /// <returns>
        /// The <see cref="BigInteger"/>.
        /// </returns>
        private BigInteger GetUnscaledValue()
        {
            if (_intVal == null)
                _intVal = BigInteger.ValueOf(_smallValue);

            return _intVal;
        }

        /// <summary>
        /// It returns the value 0 with the most approximated scale of type int
        /// </summary>
        /// 
        /// <param name="LongScale">The scale to which the value 0 will be scaled</param>
        /// 
        /// <returns>
        /// The value 0 scaled by the closer scale of type int
        /// </returns>
        private static BigDecimal GetZeroScaledBy(long LongScale)
        {
            if (LongScale == (int)LongScale)
                return ValueOf(0, (int)LongScale);

            if (LongScale >= 0)
                return new BigDecimal(0, int.MaxValue);

            return new BigDecimal(0, int.MinValue);
        }

        /// <summary>
        /// It does all rounding work of the public method Round(MathContext), performing an inplace rounding without creating a new object.
        /// </summary>
        /// 
        /// <param name="Context">MathContext for perform the rounding</param>
        private void InplaceRound(MathContext Context)
        {
            int mcPrecision = Context.Precision;

            if (AproxPrecision() - mcPrecision <= 0 || mcPrecision == 0)
                return;

            int discardedPrecision = Precision - mcPrecision;

            // If no rounding is necessary it returns immediately
            if (discardedPrecision <= 0)
                return;

            // When the number is small perform an efficient rounding
            if (_bitLength < 64)
            {
                SmallRound(Context, discardedPrecision);
                return;
            }

            // Getting the integer part and the discarded fraction
            BigInteger sizeOfFraction = Multiplication.PowerOf10(discardedPrecision);
            BigInteger[] integerAndFraction = GetUnscaledValue().DivideAndRemainder(sizeOfFraction);
            long newScale = (long)_scale - discardedPrecision;
            int compRem;
            BigDecimal tempBD;

            // If the discarded fraction is non-zero, perform rounding
            if (integerAndFraction[1].Signum() != 0)
            {
                // To check if the discarded fraction >= 0.5
                compRem = integerAndFraction[1].Abs().ShiftLeftOneBit().CompareTo(sizeOfFraction);

                // To look if there is a carry
                compRem = RoundingBehavior(
                    integerAndFraction[0].TestBit(0) ? 1 : 0,
                    integerAndFraction[1].Signum() * (5 + compRem),
                    Context.RoundingMode);
                if (compRem != 0)
                    integerAndFraction[0] = integerAndFraction[0].Add(BigInteger.ValueOf(compRem));

                tempBD = new BigDecimal(integerAndFraction[0]);

                // If after to add the increment the precision changed, we normalize the size
                if (tempBD.Precision > mcPrecision)
                {
                    integerAndFraction[0] = integerAndFraction[0].Divide(BigInteger.Ten);
                    newScale--;
                }
            }

            // To update all internal fields
            _scale = ToIntScale(newScale);
            _precision = mcPrecision;
            SetUnscaledValue(integerAndFraction[0]);
        }

        /// <summary>
        /// Test if the value is Not a Number
        /// </summary>
        /// 
        /// <param name="Value">The value to test</param>
        /// 
        /// <returns>True if NaN, otherwise false</returns>
        private static bool IsNaN(double Value)
        {
            return Value != Value;
        }

        /// <summary>
        /// Test if the value is negative zero
        /// </summary>
        /// 
        /// <param name="Value">The value to test</param>
        /// 
        /// <returns>True if negative zero, otherwise false</returns>
        internal static bool IsNegativeZero(double Value)
        {
            return (1.0 / Value) == double.NegativeInfinity;
        }

        /// <summary>
        /// Is BigDecimal zero
        /// </summary>
        /// 
        /// <returns>
        /// True if BigDecimal is zero, otherwise fals
        /// </returns>
        private bool IsZero()
        {
            // Watch out: -1 has a bitLength=0
            return _bitLength == 0 && _smallValue != -1;
        }

        /// <summary>
        /// Compare two longs
        /// </summary>
        /// 
        /// <param name="A">The first value</param>
        /// <param name="B">The second value</param>
        /// 
        /// <returns>
        /// Returns 1 for A more than B, -1 for A less B, and 0 for equal
        /// </returns>
        private static int LongCompareTo(long A, long B)
        {
            return A > B ? 1 : (A < B ? -1 : 0);
        }

        /// <summary>
        /// Returns a new BigDecimal instance where the decimal point has been moved to the right based on the scale.
        /// </summary>
        /// 
        /// <param name="NewScale">Scale of the result returned</param>
        /// 
        /// <returns>
        /// BigDecimal
        /// </returns>
        private BigDecimal MovePoint(long NewScale)
        {
            if (IsZero())
                return GetZeroScaledBy(System.Math.Max(NewScale, 0));

            // When:  'n'== Integer.MIN_VALUE  isn't possible to call to movePointRight(-n)  
            // since  -Integer.MIN_VALUE == Integer.MIN_VALUE
            if (NewScale >= 0)
            {
                if (_bitLength < 64)
                    return ValueOf(_smallValue, ToIntScale(NewScale));

                return new BigDecimal(GetUnscaledValue(), ToIntScale(NewScale));
            }

            if (-NewScale < _longTenPow.Length && _bitLength + _longTenPowBitLength[(int)-NewScale] < 64)
                return ValueOf(_smallValue * _longTenPow[(int)-NewScale], 0);

            return new BigDecimal(Multiplication.MultiplyByTenPow(GetUnscaledValue(), (int)-NewScale), 0);
        }

        /// <summary>
        /// Return an increment that can be -1, 0, or 1, depending of RoundingMode
        /// </summary>
        /// 
        /// <param name="ParityBit">Can be 0 or 1, it's only used in the case HALF_EVEN</param>
        /// <param name="Fraction">The type of rounding Mantisa to be analyzed</param>
        /// <param name="RoundingMode">The rounding mode</param>
        /// 
        /// <returns>
        /// Returns the carry propagated after rounding
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException"></exception>
        private static int RoundingBehavior(int ParityBit, int Fraction, RoundingModes RoundingMode)
        {
            int increment = 0; // the carry after rounding

            switch (RoundingMode)
            {
                case RoundingModes.Unnecessary:
                    if (Fraction != 0)
                        throw new ArithmeticException("Rounding necessary");
                    break;
                case RoundingModes.Up:
                    increment = System.Math.Sign(Fraction);
                    break;
                case RoundingModes.Down:
                    break;
                case RoundingModes.Ceiling:
                    increment = System.Math.Max(System.Math.Sign(Fraction), 0);
                    break;
                case RoundingModes.Floor:
                    increment = System.Math.Min(System.Math.Sign(Fraction), 0);
                    break;
                case RoundingModes.HalfUp:
                    if (System.Math.Abs(Fraction) >= 5)
                        increment = System.Math.Sign(Fraction);
                    break;
                case RoundingModes.HalfDown:
                    if (System.Math.Abs(Fraction) > 5)
                        increment = System.Math.Sign(Fraction);
                    break;
                case RoundingModes.HalfEven:
                    if (System.Math.Abs(Fraction) + ParityBit > 5)
                        increment = System.Math.Sign(Fraction);
                    break;
            }
            return increment;
        }

        /// <summary>
        /// The set unscaled value
        /// </summary>
        /// <param name="unscaledValue">
        /// The unscaled value
        /// </param>
        private void SetUnscaledValue(BigInteger unscaledValue)
        {
            _intVal = unscaledValue;
            _bitLength = unscaledValue.BitLength;

            if (_bitLength < 64)
                _smallValue = unscaledValue.ToInt64();
        }

        /// <summary>
        /// This method implements an efficient rounding for numbers which unscaled value fits in the type long.
        /// </summary>
        /// 
        /// <param name="Context">The context to use</param>
        /// <param name="DiscardedPrecision">The number of decimal digits that are discarded</param>
        private void SmallRound(MathContext Context, int DiscardedPrecision)
        {
            long sizeOfFraction = _longTenPow[DiscardedPrecision];
            long newScale = (long)_scale - DiscardedPrecision;
            long unscaledVal = _smallValue;
            // Getting the integer part and the discarded fraction
            long integer = unscaledVal / sizeOfFraction;
            long fraction = unscaledVal % sizeOfFraction;
            int compRem;

            // If the discarded fraction is non-zero perform rounding
            if (fraction != 0)
            {
                // To check if the discarded fraction >= 0.5
                compRem = LongCompareTo(System.Math.Abs(fraction) << 1, sizeOfFraction);
                // To look if there is a carry
                integer += RoundingBehavior(((int)integer) & 1, System.Math.Sign(fraction) * (5 + compRem), Context.RoundingMode);

                // If after to add the increment the precision changed, we normalize the size
                if (System.Math.Log10(System.Math.Abs(integer)) >= Context.Precision)
                {
                    integer /= 10;
                    newScale--;
                }
            }

            // update all internal fields
            _scale = ToIntScale(newScale);
            _precision = Context.Precision;
            _smallValue = integer;
            _bitLength = BitLength(integer);
            _intVal = null;
        }

        /// <summary>
        /// It tests if a scale of type long fits in 32 bits.
        /// It returns the same scale being casted to int type when is possible, otherwise throws an exception.
        /// </summary>
        /// 
        /// <param name="LongScale">A 64 bit scale</param>
        /// <returns>
        /// A 32 bit scale when is possible
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Throws ArithmeticException when Scale doesn't fit in int type</exception>
        private static int ToIntScale(long LongScale)
        {
            if (LongScale < int.MinValue)
                throw new ArithmeticException("Overflow");
            else if (LongScale > int.MaxValue)
                throw new ArithmeticException("Underflow");
            else
                return (int)LongScale;
        }

        /// <summary>
        /// The to string internal.
        /// </summary>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        private string ToStringInternal()
        {
            if (_bitLength < 32)
            {
                _toStringImage = Conversion.ToDecimalScaledString(_smallValue, _scale);
                return _toStringImage;
            }

            string intString = GetUnscaledValue().ToString();
            if (_scale == 0)
                return intString;

            int begin = (GetUnscaledValue().Signum() < 0) ? 2 : 1;
            int end = intString.Length;
            long exponent = -(long)_scale + end - begin;
            StringBuilder result = new StringBuilder();

            result.Append(intString);
            if ((_scale > 0) && (exponent >= -6))
            {
                if (exponent >= 0)
                {
                    result.Insert(end - _scale, '.');
                }
                else
                {
                    result.Insert(begin - 1, "0."); // $NON-NLS-1$
                    result.Insert(begin + 1, _chZeros, 0, -(int)exponent - 1);
                }
            }
            else
            {
                if (end - begin >= 1)
                {
                    result.Insert(begin, '.');
                    end++;
                }

                result.Insert(end, 'E');
                if (exponent > 0)
                    result.Insert(++end, '+');

                result.Insert(++end, Convert.ToString(exponent));
            }

            _toStringImage = result.ToString();

            return _toStringImage;
        }

        /// <summary>
        /// Counts the number of bits of value and checks if it's out of the range of the primitive type.
        /// </summary>
        /// 
        /// <param name="BitLengthOfType">umber of bits of the type whose value will be calculated</param>
        /// 
        /// <returns>
        /// The exact value of the integer part of BigDecimal when is possible
        /// </returns>
        /// 
        /// <exception cref="ArithmeticException">Throws if rounding is necessary or the number don't fit in the primitive type</exception>
        private long ValueExact(int BitLengthOfType)
        {
            BigInteger bigInteger = ToBigIntegerExact();

            // It fits in the primitive type
            if (bigInteger.BitLength < BitLengthOfType)
                return bigInteger.ToInt64();

            throw new ArithmeticException("Rounding necessary");
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Returns true if Obj is a BigDecimal instance and if this instance is equal to this big decimal.
        /// <para>Two big decimals are equal if their unscaled value and their scale is equal.
        /// For example, <c>1.0 (10*10^(-1))</c> is not equal to <c>1.00 (100*10^(-2))</c>.
        /// Similarly, zero instances are not equal if their scale differs.</para>
        /// </summary>
        /// 
        /// <param name="Obj">Object to be compared with this</param>
        /// 
        /// <returns>
        /// Returns true if Obj is a BigDecimal and this == Obj
        /// </returns>
        public override bool Equals(object Obj)
        {
            if (this == Obj)
                return true;

            if (Obj is BigDecimal)
            {
                BigDecimal x1 = (BigDecimal)Obj;
                return x1._scale == _scale && (_bitLength < 64 ? (x1._smallValue == _smallValue) : _intVal.Equals(x1._intVal));
            }

            return false;
        }

        /// <summary>
        /// Returns a hash code for this BigDecimal
        /// </summary>
        /// 
        /// <returns>
        /// Hash code for this
        /// </returns>
        public override int GetHashCode()
        {
            if (_hashCode != 0)
                return _hashCode;

            if (_bitLength < 64)
            {
                _hashCode = (int)(_smallValue & 0xffffffff);
                _hashCode = 33 * _hashCode + (int)((_smallValue >> 32) & 0xffffffff);
                _hashCode = 17 * _hashCode + _scale;
                return _hashCode;
            }

            _hashCode = 17 * _intVal.GetHashCode() + _scale;

            return _hashCode;
        }

        /// <summary>
        /// Returns a canonical string representation of this BigDecimal.
        /// <para>If necessary, scientific notation is used.
        /// This representation always prints all significant digits of this value.
        /// If the scale is negative or if Scale - precision >= 6 then scientific notation is used.</para>
        /// </summary>
        /// 
        /// <returns>
        /// Returns a string representation of this in scientific notation if necessary
        /// </returns>
        public override string ToString()
        {
            if (_toStringImage != null)
                return _toStringImage;

            return ToStringInternal();
        }
        #endregion

        #region Serialize
        /// <summary>
        /// Initializes a new instance of the <see cref="BigDecimal"/> class
        /// </summary>
        /// 
        /// <param name="Info">The info</param>
        /// <param name="Context">The context</param>
        private BigDecimal(SerializationInfo Info, StreamingContext Context)
        {
            _intVal = (BigInteger)Info.GetValue("intVal", typeof(BigInteger));
            _scale = Info.GetInt32("scale");
            _bitLength = _intVal.BitLength;

            if (_bitLength < 64)
                _smallValue = _intVal.ToInt64();
        }

        /// <summary>
        /// The get object data
        /// </summary>
        /// <param name="Info">The info</param>
        /// <param name="Context">The context</param>
        void ISerializable.GetObjectData(SerializationInfo Info, StreamingContext Context)
        {
            GetUnscaledValue();
            Info.AddValue("intVal", _intVal, typeof(BigInteger));
            Info.AddValue("scale", _scale);
        }
        #endregion

        #region IConvertible
        TypeCode IConvertible.GetTypeCode()
        {
            return TypeCode.Object;
        }

        bool IConvertible.ToBoolean(IFormatProvider Provider)
        {
            int value = ToInt32();

            if (value == 1)
                return true;
            if (value == 0)
                return false;

            throw new InvalidCastException();
        }

        char IConvertible.ToChar(IFormatProvider Provider)
        {
            short value = ToInt16Exact();
            return (char)value;
        }

        sbyte IConvertible.ToSByte(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        byte IConvertible.ToByte(IFormatProvider Provider)
        {
            int value = ToInt32();

            if (value > byte.MaxValue || value < byte.MinValue)
                throw new InvalidCastException();

            return (byte)value;
        }

        short IConvertible.ToInt16(IFormatProvider Provider)
        {
            return ToInt16Exact();
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
            throw new NotSupportedException();
        }

        DateTime IConvertible.ToDateTime(IFormatProvider Provider)
        {
            throw new NotSupportedException();
        }

        string IConvertible.ToString(IFormatProvider Provider)
        {
            return ToString();
        }

        object IConvertible.ToType(Type conversionType, IFormatProvider Provider)
        {
            if (conversionType == typeof(bool))
                return (this as IConvertible).ToBoolean(Provider);
            if (conversionType == typeof(byte))
                return (this as IConvertible).ToByte(Provider);
            if (conversionType == typeof(short))
                return ToInt16Exact();
            if (conversionType == typeof(int))
                return ToInt32();
            if (conversionType == typeof(long))
                return ToInt64();
            if (conversionType == typeof(float))
                return ToSingle();
            if (conversionType == typeof(double))
                return ToDouble();
            if (conversionType == typeof(BigInteger))
                return ToBigInteger();

            throw new NotSupportedException();
        }
        #endregion

        #region Operators
        /// <summary>
        /// Add two <see cref="BigDecimal"/> values.
        /// <para>The scale of the result is the maximum of the scales of the two arguments.</para>
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns>Returns a new BigDecimal whose value is <c>A + B</c>.</returns>
        public static BigDecimal operator +(BigDecimal A, BigDecimal B)
        {
            return A.Add(B);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>A - B</c>.
        /// <para>The scale of the result is the maximum of the scales of the two arguments.</para>
        /// </summary>
        /// 
        /// <param name="A">The first value A</param>
        /// <param name="B">The second value B</param>
        /// 
        /// <returns><c>A - B</c></returns>
        public static BigDecimal operator -(BigDecimal A, BigDecimal B)
        {
            return A.Subtract(B);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>A / B</c>.
        /// <para>The scale of the result is the difference of the scales of this and Divisor.
        /// If the exact result requires more digits, then the scale is adjusted accordingly.
        /// For example, <c>1/128 = 0.0078125</c> which has a scale of 7 and precision 5.</para>
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The divisor B</param>
        /// 
        /// <returns><c>A / B</c></returns>
        public static BigDecimal operator /(BigDecimal A, BigDecimal B)
        {
            return A.Divide(B);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>A % B</c>.
        /// <para>The remainder is defined as <c>A - DivideToIntegralValue(B) * B</c>.</para>
        /// </summary>
        /// 
        /// <param name="A">The value</param>
        /// <param name="B">The divisor</param>
        /// 
        /// <returns><c>A % B</c></returns>
        public static BigDecimal operator %(BigDecimal A, BigDecimal B)
        {
            return A.Remainder(B);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>this * Multiplicand</c>.
        /// <para>The scale of the result is the sum of the scales of the two arguments</para>
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The multiplicand</param>
        /// 
        /// <returns><c>A * B</c></returns>
        public static BigDecimal operator *(BigDecimal A, BigDecimal B)
        {
            return A.Multiply(B);
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is <c>+A</c>.
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// 
        /// <returns><c>+A</c></returns>
        public static BigDecimal operator +(BigDecimal A)
        {
            return A.Plus();
        }

        /// <summary>
        /// Returns a new BigDecimal whose value is the <c>-A</c>.
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// 
        /// <returns><c>-A</c></returns>
        public static BigDecimal operator -(BigDecimal A)
        {
            return A.Negate();
        }

        /// <summary>
        /// Returns true if "A" is a BigDecimal instance and if this instance is equal to "B".
        /// <para>Two big decimals are equal if their unscaled value and their scale is equal.
        /// For example, 1.0 (10*10^(-1)) is not equal to 1.00 (100*10^(-2)).
        /// Similarly, zero instances are not equal if their scale differs.</para>
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The value B</param>
        /// 
        /// <returns>Returns true if "B" is a BigDecimal and A == B</returns>
        public static bool operator ==(BigDecimal A, BigDecimal B)
        {
            if ((object)A == null && (object)B == null)
                return true;

            if ((object)A == null)
                return false;

            return A.Equals(B);
        }

        /// <summary>
        /// Returns true if BigDecimal value "A" is not equal to BigDecimal "B".
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The value B</param>
        /// 
        /// <returns>Returns true if <c>A != B</c>, otherwise false</returns>
        public static bool operator !=(BigDecimal A, BigDecimal B)
        {
            return !(A == B);
        }

        /// <summary>
        /// Returns true if BigDecimal value "A" is more than BigDecimal value "B"
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The value B</param>
        /// 
        /// <returns>Returns true if <c>A > B</c>, otherwise false</returns>
        public static bool operator >(BigDecimal A, BigDecimal B)
        {
            return A.CompareTo(B) < 0;
        }

        /// <summary>
        /// Returns true if BigDecimal value "A" is less than BigDecimal value "B"
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The value B</param>
        /// 
        /// <returns>Returns true if <c>A &lt; B</c>, otherwise false</returns>
        public static bool operator <(BigDecimal A, BigDecimal B)
        {
            return A.CompareTo(B) > 0;
        }

        /// <summary>
        /// Returns true if BigDecimal value "A" is more than or equal to BigDecimal value "B"
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The value B</param>
        /// 
        /// <returns>Returns true if <c>A >= B</c>, otherwise false</returns>
        public static bool operator >=(BigDecimal A, BigDecimal B)
        {
            return A == B || A > B;
        }

        /// <summary>
        /// Returns true if BigDecimal value "A" is less than or equal to BigDecimal value "B"
        /// </summary>
        /// 
        /// <param name="A">The value A</param>
        /// <param name="B">The value B</param>
        /// 
        /// <returns>Returns true if <c>A &lt;= B</c>, otherwise false</returns>
        public static bool operator <=(BigDecimal A, BigDecimal B)
        {
            return A == B || A < B;
        }
        #endregion

        #region Implicit Operators
        /// <summary>
        /// Returns this BigDecimal as a short value if it has no fractional part 
        /// and if its value fits to the short range ([-2^{15}..2^{15}-1]).
        /// <para>If these conditions are not met, an ArithmeticException is thrown.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns this BigDecimal as a short value</returns>
        public static implicit operator Int16(BigDecimal X)
        {
            return X.ToInt16Exact();
        }

        /// <summary>
        /// Returns this BigDecimal as an int value.
        /// <para>If the integral part of this is too big to be represented as an int, then this % 2^32 is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns this BigDecimal as an int value</returns>
        public static implicit operator Int32(BigDecimal X)
        {
            return X.ToInt32();
        }

        /// <summary>
        /// Returns this BigDecimal as an long value. Any fractional part is discarded.
        /// <para>If the integral part of this is too big to be represented as an long, then this % 2^64 is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns this BigDecimal as a long value</returns>
        public static implicit operator Int64(BigDecimal X)
        {
            return X.ToInt64();
        }

        /// <summary>
        /// Returns this BigDecimal as a float value.
        /// <para>If this is too big to be represented as an float, 
        /// then Float.POSITIVE_INFINITY or Float.NEGATIVE_INFINITY is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns this BigDecimal as a float value</returns>
        /// 
        /// <remarks>
        /// <para>Note, that if the unscaled value has more than 24 significant digits, 
        /// then this decimal cannot be represented exactly in a float variable.
        /// In this case the result is rounded.
        /// For example, if the instance <c>x1 = new BigDecimal("0.1")</c> cannot be represented exactly as a float, 
        /// and thus <c>x1.Equals(new BigDecimal(x1.FloatValue())</c> returns false for this case.
        /// Similarly, if the instance <c>new BigDecimal(16777217)</c> is converted to a float, the result is 1.6777216E7.</para>
        /// </remarks>
        public static implicit operator Single(BigDecimal X)
        {
            return X.ToSingle();
        }

        /// <summary>
        /// Returns this BigDecimal as a double value.
        /// <para>If this is too big to be represented as an float, then Double.POSITIVE_INFINITY or Double.NEGATIVE_INFINITY is returned.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns this BigDecimal as a double value</returns>
        /// 
        /// <remarks>
        /// <para>Note, that if the unscaled value has more than 53 significant digits, 
        /// then this decimal cannot be represented exactly in a double variable.
        /// In this case the result is rounded.
        /// For example, if the instance <c>x1 = new BigDecimal("0.1")</c> cannot be 
        /// represented exactly as a double, and thus <c>x1.Equals(new BigDecimal(x1.ToDouble())</c> 
        /// returns false for this case.
        /// Similarly, if the instance <c>new BigDecimal(9007199254740993L)</c>c> is converted to a double, 
        /// the result is 9.007199254740992E15.</para>
        /// </remarks>
        public static implicit operator Double(BigDecimal X)
        {
            return X.ToDouble();
        }

        /// <summary>
        /// Returns this BigDecimal as a big integer instance.
        /// <para>A fractional part is discarded.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns this BigDecimal as a BigInteger instance</returns>
        public static implicit operator BigInteger(BigDecimal X)
        {
            return X.ToBigInteger();
        }

        /// <summary>
        /// Returns a canonical string representation of this BigDecimal.
        /// <para>If necessary, scientific notation is used.
        /// This representation always prints all significant digits of this value.
        /// If the scale is negative or if Scale - precision >= 6 then scientific notation is used.</para>
        /// </summary>
        /// 
        /// <param name="X">The BigDecimal to convert</param>
        /// 
        /// <returns>Returns a string representation of this in scientific notation if necessary</returns>
        public static implicit operator String(BigDecimal X)
        {
            return X.ToString();
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given long value.
        /// <para>The scale of the result is 0.</para>
        /// </summary>
        /// 
        /// <param name="Value">The long value to be converted to a BigDecimal instance</param>
        /// 
        /// <returns>A new BigDecimal instance</returns>
        public static implicit operator BigDecimal(long Value)
        {
            return new BigDecimal(Value);
        }

        /// <summary>
        /// Constructs a new <see cref="BigDecimal"/> instance from the 64bit double value. 
        /// <para>The constructed big decimal is equivalent to the given double.</para>
        /// </summary>
        /// 
        /// <param name="Value">The double value to be converted to a <see cref="BigDecimal"/> instance</param>
        /// 
        /// <returns>A new BigDecimal instance</returns>
        /// 
        /// <remarks>
        /// For example, <c>new BigDecimal(0.1)</c> is equal to <c>0.1000000000000000055511151231257827021181583404541015625</c>. 
        /// This happens as <c>0.1</c> cannot be represented exactly in binary.
        /// <para>To generate a big decimal instance which is equivalent to <c>0.1</c> use the <see cref="BigDecimal(string)"/> constructor.</para>
        /// </remarks>
        /// 
        /// <exception cref="FormatException">Thown if <paramref name="Value"/> is infinity or not a number.</exception>
        public static implicit operator BigDecimal(double Value)
        {
            return new BigDecimal(Value);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given int value.
        /// <para>The scale of the result is 0.</para>
        /// </summary>
        /// 
        /// <param name="Value">The int value to be converted to a BigDecimal instance</param>
        /// 
        /// <returns>A new BigDecimal instance</returns>
        public static implicit operator BigDecimal(int Value)
        {
            return new BigDecimal(Value);
        }

        /// <summary>
        /// Constructs a new BigDecimal instance from the given BigInteger value.
        /// <para>The scale of the result is 0</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be converted to a BigDecimal instance</param>
        /// 
        /// <returns>A new BigDecimal instance</returns>
        public static implicit operator BigDecimal(BigInteger Value)
        {
            return new BigDecimal(Value);
        }
        #endregion
    }
}