#region Directives
using System;
using System.Text;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric 
{
	/// <summary>
	/// Static library that provides BigInteger base conversion from/to any integer represented in an String Object
	/// </summary>
    internal sealed class Conversion
    {
        #region Fields
        // Holds the maximal exponent for each radix, so that radix DigitFitInInt[radix]  fit in an int (32 bits).
        internal static readonly int[] DigitFitInInt = 
        { 
            -1, -1, 31, 19, 15, 13, 11, 11, 10, 9, 9, 8, 8, 8, 8, 7, 7,
            7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5 
        };

        //bigRadices values are precomputed maximal powers of radices (integer numbers from 2 to 36) that fit into unsigned int (32 bits). bigRadices[0] = 2 ^ 31, bigRadices[8] = 10 ^ 9, etc.
        internal static readonly int[] BigRadices = 
        { 
            -2147483648, 1162261467, 1073741824, 1220703125, 362797056, 1977326743, 1073741824, 387420489, 
            1000000000, 214358881, 429981696, 815730721, 1475789056, 170859375, 268435456, 410338673, 612220032, 
            893871739, 1280000000, 1801088541, 113379904, 148035889, 191102976, 244140625, 308915776, 387420489, 
            481890304, 594823321, 729000000, 887503681, 1073741824, 1291467969, 1544804416, 1838265625, 60466176 
        };
        #endregion

        #region Constructor
        private Conversion()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Returns this BigInteger as an double value.
        /// <para>If this is too big to be represented as an double, then Double.POSITIVE_INFINITY or 
        /// Double.NEGATIVE_INFINITY} is returned.</para>
        /// </summary>
        /// 
        /// <param name="Value">The value to convert</param>
        /// 
        /// <returns>Returns a BigInteger as a double value</returns>
        /// 
        /// <remarks>
        /// Note, that not all integers x in the range [-Double.MAX_VALUE, Double.MAX_VALUE] can be represented as a double. 
        /// The double representation has a mantissa of length 53. For example, 2^53+1 = 9007199254740993 is returned as double 9007199254740992.0.
        /// </remarks>
        internal static double BigInteger2Double(BigInteger Value)
        {
            // val.bitLength() < 64
            if ((Value._numberLength < 2) || ((Value._numberLength == 2) && (Value._digits[1] > 0)))
                return Value.ToInt64();
            
            // val.bitLength() >= 33 * 32 > 1024
            if (Value._numberLength > 32)
                return ((Value._sign > 0) ? Double.PositiveInfinity : Double.NegativeInfinity);
            
            int bitLen = Value.Abs().BitLength;
            long exponent = bitLen - 1;
            int delta = bitLen - 54;
            // We need 54 top bits from this, the 53th bit is always 1 in lVal.
            long lVal = Value.Abs().ShiftRight(delta).ToInt64();

             // Take 53 bits from lVal to mantissa. The least significant bit is needed for rounding.
            long mantissa = lVal & 0x1FFFFFFFFFFFFFL;
            if (exponent == 1023)
            {
                if (mantissa == 0X1FFFFFFFFFFFFFL)
                    return ((Value._sign > 0) ? Double.PositiveInfinity : Double.NegativeInfinity);
                
                if (mantissa == 0x1FFFFFFFFFFFFEL)
                    return ((Value._sign > 0) ? Double.MaxValue : -Double.MaxValue);
                
            }
            // Round the mantissa
            if (((mantissa & 1) == 1)  && (((mantissa & 2) == 2) || BitLevel.NonZeroDroppedBits(delta, Value._digits)))
                mantissa += 2;
            
            mantissa >>= 1; // drop the rounding bit
            // long resSign = (val.sign < 0) ? 0x8000000000000000L : 0;
            long resSign = (Value._sign < 0) ? Int64.MinValue : 0;
            exponent = ((1023 + exponent) << 52) & 0x7FF0000000000000L;
            long result = resSign | exponent | mantissa;

            return BitConverter.Int64BitsToDouble(result);
        }

        /// <summary>
        /// Returns a string containing a string representation of this  BigInteger with base radix.
        /// <para>If Radix &lt; CharHelper.MIN_RADIX} or Radix > CharHelper.MAX_RADIX then a decimal representation is returned.
        /// The CharHelpers of the string representation are generated with method CharHelper.forDigit.</para>
        /// </summary>
        /// 
        /// <param name="Value">The value to convert</param>
        /// <param name="Radix">Base to be used for the string representation</param>
        /// 
        /// <returns>Returns a string representation of this with radix 10</returns>
        internal static string BigInteger2String(BigInteger Value, int Radix)
        {
            int sign = Value._sign;
            int numberLength = Value._numberLength;
            int[] digits = Value._digits;

            if (sign == 0)
                return "0"; //$NON-NLS-1$
            
            if (numberLength == 1)
            {
                int highDigit = digits[numberLength - 1];
                long v = highDigit & 0xFFFFFFFFL;
                // Long.ToString has different semantic from C# for negative numbers
                if (sign < 0)
                    return "-" + Convert.ToString(v, Radix);
                
                return Convert.ToString(v, Radix);
            }

            if ((Radix == 10) || (Radix < CharUtils.MIN_RADIX)  || (Radix > CharUtils.MAX_RADIX))
                return Value.ToString();

            double bitsForRadixDigit;
            bitsForRadixDigit = System.Math.Log(Radix) / System.Math.Log(2);
            int resLengthInChars = (int)(Value.Abs().BitLength / bitsForRadixDigit + ((sign < 0) ? 1 : 0)) + 1;
            char[] result = new char[resLengthInChars];
            int currentChar = resLengthInChars;
            int resDigit;

            if (Radix != 16)
            {
                int[] temp = new int[numberLength];
                Array.Copy(digits, 0, temp, 0, numberLength);
                int tempLen = numberLength;
                int charsPerInt = DigitFitInInt[Radix];
                int i;
                // get the maximal power of radix that fits in int
                int bigRadix = BigRadices[Radix - 2];
                while (true)
                {
                    // divide the array of digits by bigRadix and convert remainders
                    // to CharHelpers collecting them in the char array
                    resDigit = Division.DivideArrayByInt(temp, temp, tempLen, bigRadix);
                    int previous = currentChar;
                    do
                    {
                        result[--currentChar] = CharUtils.ForDigit(resDigit % Radix, Radix);
                    } while (((resDigit /= Radix) != 0) && (currentChar != 0));

                    int delta = charsPerInt - previous + currentChar;
                    for (i = 0; i < delta && currentChar > 0; i++)
                        result[--currentChar] = '0';
                    
                    for (i = tempLen - 1; (i > 0) && (temp[i] == 0); i--)
                    {
                        ;
                    }
                    tempLen = i + 1;

                    if ((tempLen == 1) && (temp[0] == 0)) // the quotient is 0
                        break;
                }
            }
            else
            {
                // radix == 16
                for (int i = 0; i < numberLength; i++)
                {
                    for (int j = 0; (j < 8) && (currentChar > 0); j++)
                    {
                        resDigit = digits[i] >> (j << 2) & 0xf;
                        result[--currentChar] = CharUtils.ForDigit(resDigit, 16);
                    }
                }
            }
            while (result[currentChar] == '0')
                currentChar++;
            
            if (sign == -1)
                result[--currentChar] = '-';
            
            return new String(result, currentChar, resLengthInChars - currentChar);
        }

        /// <summary>
        /// Returns a string representation of this BigInteger in decimal form
        /// </summary>
        /// 
        /// <param name="Value">The value to convert</param>
        /// <param name="Scale">The scale</param>
        /// 
        /// <returns>Returns a string representation of this in decimal form</returns>
        internal static String ToDecimalScaledString(BigInteger Value, int Scale)
        {   
            //ToDo: too proceedural, break this up.. j.u.
            int sign = Value._sign;
            int numberLength = Value._numberLength;
            int[] digits = Value._digits;
            int resLengthInChars;
            int currentChar;
            char[] result;

            if (sign == 0)
            {
                switch (Scale)
                {
                    case 0:
                        return "0"; //$NON-NLS-1$
                    case 1:
                        return "0.0"; //$NON-NLS-1$
                    case 2:
                        return "0.00"; //$NON-NLS-1$
                    case 3:
                        return "0.000"; //$NON-NLS-1$
                    case 4:
                        return "0.0000"; //$NON-NLS-1$
                    case 5:
                        return "0.00000"; //$NON-NLS-1$
                    case 6:
                        return "0.000000"; //$NON-NLS-1$
                    default:
                        {
                            StringBuilder result2 = new StringBuilder();
                            if (Scale < 0)
                                result2.Append("0E+"); //$NON-NLS-1$
                            else
                                result2.Append("0E"); //$NON-NLS-1$
                            
                            result2.Append(-Scale);
                            return result2.ToString();
                        }
                }
            }
            // one 32-bit unsigned value may contains 10 decimal digits
            resLengthInChars = numberLength * 10 + 1 + 7;
            // Explanation why +1+7: +1 - one char for sign if needed. +7 - 
            // For "special case 2" (see below) we have 7 free chars for inserting necessary scaled digits.
            result = new char[resLengthInChars + 1];
            // allocated [resLengthInChars+1] CharHelpers.
            // a free latest CharHelper may be used for "special case 1" (see below)
            currentChar = resLengthInChars;
            if (numberLength == 1)
            {
                int highDigit = digits[0];
                if (highDigit < 0)
                {
                    long v = highDigit & 0xFFFFFFFFL;
                    do
                    {
                        long prev = v;
                        v /= 10;
                        result[--currentChar] = (char)(0x0030 + ((int)(prev - v * 10)));
                    } while (v != 0);
                }
                else
                {
                    int v = highDigit;
                    do
                    {
                        int prev = v;
                        v /= 10;
                        result[--currentChar] = (char)(0x0030 + (prev - v * 10));
                    } while (v != 0);
                }
            }
            else
            {
                int[] temp = new int[numberLength];
                int tempLen = numberLength;
                Array.Copy(digits, 0, temp, 0, tempLen);

                while (true)
                {
                    // divide the array of digits by bigRadix and convert remainders
                    // to CharHelpers collecting them in the char array
                    long result11 = 0;
                    for (int i1 = tempLen - 1; i1 >= 0; i1--)
                    {
                        long temp1 = (result11 << 32) + (temp[i1] & 0xFFFFFFFFL);
                        long res = DivideLongByBillion(temp1);
                        temp[i1] = (int)res;
                        result11 = (int)(res >> 32);
                    }

                    int resDigit = (int)result11;
                    int previous = currentChar;
                    do
                    {
                        result[--currentChar] = (char)(0x0030 + (resDigit % 10));
                    } while (((resDigit /= 10) != 0) && (currentChar != 0));

                    int delta = 9 - previous + currentChar;
                    for (int i = 0; (i < delta) && (currentChar > 0); i++)
                        result[--currentChar] = '0';
             
                    int j = tempLen - 1;
                    for (; temp[j] == 0; j--)
                    {
                        if (j == 0) // means temp[0] == 0
                            goto BIG_LOOP;
                    }
                    tempLen = j + 1;
                }
            BIG_LOOP:
                while (result[currentChar] == '0')
                {
                    currentChar++;
                }
            }

            bool negNumber = (sign < 0);
            int exponent = resLengthInChars - currentChar - Scale - 1;
            if (Scale == 0)
            {
                if (negNumber)
                    result[--currentChar] = '-';
                
                return new String(result, currentChar, resLengthInChars - currentChar);
            }

            if ((Scale > 0) && (exponent >= -6))
            {
                if (exponent >= 0)
                {
                    // special case 1
                    int insertPoint = currentChar + exponent;
                    for (int j = resLengthInChars - 1; j >= insertPoint; j--)
                        result[j + 1] = result[j];
                    
                    result[++insertPoint] = '.';
                    if (negNumber)
                        result[--currentChar] = '-';
                    
                    return new String(result, currentChar, resLengthInChars - currentChar + 1);
                }

                // special case 2
                for (int j = 2; j < -exponent + 1; j++)
                    result[--currentChar] = '0';
                
                result[--currentChar] = '.';
                result[--currentChar] = '0';
                if (negNumber)
                    result[--currentChar] = '-';
                
                return new String(result, currentChar, resLengthInChars - currentChar);
            }
            int startPoint = currentChar + 1;
            int endPoint = resLengthInChars;
            StringBuilder result1 = new StringBuilder(16 + endPoint - startPoint);

            if (negNumber)
                result1.Append('-');
            
            if (endPoint - startPoint >= 1)
            {
                result1.Append(result[currentChar]);
                result1.Append('.');
                result1.Append(result, currentChar + 1, resLengthInChars - currentChar - 1);
            }
            else
            {
                result1.Append(result, currentChar, resLengthInChars - currentChar);
            }

            result1.Append('E');
            if (exponent > 0)
                result1.Append('+');
            
            result1.Append(Convert.ToString(exponent));

            return result1.ToString();
        }

        /// <summary>
        /// Returns a string representation of this BigInteger in decimal form
        /// </summary>
        /// 
        /// <param name="Value">The value to convert</param>
        /// <param name="Scale">The scale</param>
        /// 
        /// <returns>Returns a string representation of this in decimal form</returns>
        internal static String ToDecimalScaledString(long Value, int Scale)
        {
            int resLengthInChars;
            int currentChar;
            char[] result;
            bool negNumber = Value < 0;

            if (negNumber)
                Value = -Value;
            
            if (Value == 0)
            {
                switch (Scale)
                {
                    case 0: return "0"; //$NON-NLS-1$
                    case 1: return "0.0"; //$NON-NLS-1$
                    case 2: return "0.00"; //$NON-NLS-1$
                    case 3: return "0.000"; //$NON-NLS-1$
                    case 4: return "0.0000"; //$NON-NLS-1$
                    case 5: return "0.00000"; //$NON-NLS-1$
                    case 6: return "0.000000"; //$NON-NLS-1$
                    default:
                        StringBuilder result2 = new StringBuilder();
                        if (Scale < 0)
                            result2.Append("0E+"); //$NON-NLS-1$
                        else
                            result2.Append("0E"); //$NON-NLS-1$

                        result2.Append((Scale == Int32.MinValue) ? "2147483648" : Convert.ToString(-Scale)); //$NON-NLS-1$
                        return result2.ToString();
                }
            }
            // one 32-bit unsigned value may contains 10 decimal digits
            resLengthInChars = 18;
            // Explanation why +1+7: +1 - one char for sign if needed. +7 - 
            // For "special case 2" (see below) we have 7 free chars for inserting necessary scaled digits.
            result = new char[resLengthInChars + 1];
            //  Allocated [resLengthInChars+1] CharHelpers. a free latest CharHelper may be used for "special case 1" (see below)
            currentChar = resLengthInChars;
            long v = Value;
            do
            {
                long prev = v;
                v /= 10;
                result[--currentChar] = (char)(0x0030 + (prev - v * 10));
            } while (v != 0);

            long exponent = (long)resLengthInChars - (long)currentChar - Scale - 1L;
            if (Scale == 0)
            {
                if (negNumber)
                    result[--currentChar] = '-';
                
                return new String(result, currentChar, resLengthInChars - currentChar);
            }
            if (Scale > 0 && exponent >= -6)
            {
                if (exponent >= 0)
                {
                    // special case 1
                    int insertPoint = currentChar + (int)exponent;
                    for (int j = resLengthInChars - 1; j >= insertPoint; j--)
                        result[j + 1] = result[j];
                    
                    result[++insertPoint] = '.';
                    if (negNumber)
                        result[--currentChar] = '-';
                    
                    return new String(result, currentChar, resLengthInChars - currentChar + 1);
                }

                // special case 2
                for (int j = 2; j < -exponent + 1; j++)
                    result[--currentChar] = '0';
                
                result[--currentChar] = '.';
                result[--currentChar] = '0';
                if (negNumber)
                    result[--currentChar] = '-';
                
                return new String(result, currentChar, resLengthInChars - currentChar);
            }

            int startPoint = currentChar + 1;
            int endPoint = resLengthInChars;
            StringBuilder result1 = new StringBuilder(16 + endPoint - startPoint);
            if (negNumber)
                result1.Append('-');
            
            if (endPoint - startPoint >= 1)
            {
                result1.Append(result[currentChar]);
                result1.Append('.');
                result1.Append(result, currentChar + 1, resLengthInChars - currentChar - 1);
            }
            else
            {
                result1.Append(result, currentChar, resLengthInChars - currentChar);
            }
            result1.Append('E');
            if (exponent > 0)
                result1.Append('+');
            
            result1.Append(Convert.ToString(exponent));
            return result1.ToString();
        }
        #endregion

        #region Private Methods
        private static long DivideLongByBillion(long N)
        {
            long quot;
            long rem;

            if (N >= 0)
            {
                long bLong = 1000000000L;
                quot = (N / bLong);
                rem = (N % bLong);
            }
            else
            {
                /*
                 * Make the dividend positive shifting it right by 1 bit then get
                 * the quotient an remainder and correct them properly
                 */
                long aPos = IntUtils.URShift(N, 1);
                long bPos = IntUtils.URShift(1000000000L, 1);
                quot = aPos / bPos;
                rem = aPos % bPos;
                // double the remainder and add 1 if 'a' is odd
                rem = (rem << 1) + (N & 1);
            }
            return ((rem << 32) | (quot & 0xFFFFFFFFL));
        }
        #endregion
    }
}