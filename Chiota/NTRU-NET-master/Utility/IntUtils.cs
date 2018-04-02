#region Directives
using System;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// An integer utilities class
    /// </summary>
    public static class IntUtils
    {
        #region Constants
        internal const long INFLATED = long.MinValue;
        internal static double DOUBLE_MAX = double.MaxValue;
        internal static double NEGATIVE_INFINITY = -1.0 / 0.0;
        internal static double NaN = 0.0d / 0.0;
        internal static double POSITIVE_INFINITY = 1.0 / 0.0;
        internal static long SIGNIF_BIT_MASK = 0x000FFFFFFFFFFFFFL;
        internal static long SIGN_BIT_MASK = unchecked((Int64)0x8000000000000000L);
        #endregion

        #region Enums
        internal enum CharConsts : int
        {
            MIN_RADIX = 2,
            MAX_RADIX = 36
        }

        internal enum DoubleConsts : int
        {
            EXP_BIAS = 1023,
            SIZE = 64,
            MAX_EXPONENT = 1023,
            MIN_EXPONENT = -1022,
            SIGNIFICAND_WIDTH = 53
        }

        internal enum FloatConsts : int
        {
            EXP_BIAS = 127,
            MAX_EXPONENT = 127,
            MIN_EXPONENT = -126,
            SIGN_BIT_MASK = unchecked((Int32)0x80000000),
            SIGNIF_BIT_MASK = 0x007FFFFF,
            SIGNIFICAND_WIDTH = 24,
            SIZE = 32
        }

        internal enum IntConsts : int
        {
            MIN_VALUE = unchecked((Int32)0x80000000),
            MAX_VALUE = 0x7fffffff,
            SIZE = 32
        }
        internal enum LongConsts : long
        {
            SIZE = 64,
            MIN_VALUE = unchecked((Int64)0x8000000000000000L),
            MAX_VALUE = 0x7fffffffffffffffL
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Returns the number of one-bits in the two's complement binary 
        /// representation of the specified int value. 
        /// <para>This function is sometimes referred to as the population count.</para>
        /// </summary>
        /// 
        /// <param name="X">The value whose bits are to be counted</param>
        /// 
        /// <returns>The number of one-bits in the two's complement binary representation of the specified int value</returns>
        internal static int BitCount(int X)
        {
            X = X - ((int)(uint)(X >> 1) & 0x55555555);
            X = (X & 0x33333333) + ((int)(uint)(X >> 2) & 0x33333333);
            X = (X + ((int)(uint)X >> 4)) & 0x0f0f0f0f;
            X = X + ((int)(uint)X >> 8);
            X = X + ((int)(uint)X >> 16);

            return X & 0x3f;
        }

        /// <summary>
        /// Returns the number of bits in a number
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the number of bits in a number</returns>
        internal static int BitCount(long X)
        {
            // Successively collapse alternating bit groups into a sum.
            X = ((X >> 1) & 0x5555555555555555L) + (X & 0x5555555555555555L);
            X = ((X >> 2) & 0x3333333333333333L) + (X & 0x3333333333333333L);

            int v = (int)(URShift(X, 32) + X);
            v = ((v >> 4) & 0x0f0f0f0f) + (v & 0x0f0f0f0f);
            v = ((v >> 8) & 0x00ff00ff) + (v & 0x00ff00ff);

            return ((v >> 16) & 0x0000ffff) + (v & 0x0000ffff);
        }

        /// <summary>
        /// Create a copy of an array
        /// </summary>
        /// <param name="A">The array to copy</param>
        /// 
        /// <returns>Returns the array copy</returns>
        internal static int[] Clone(int[] A)
        {
            int[] result = new int[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

        /// <summary>
        /// Convert a double to a long value
        /// </summary>
        /// 
        /// <param name="X">Double to convert</param>
        /// 
        /// <returns>Long value representation</returns>
        internal static long DoubleToLong(double X)
        {
            if (X != X)
                return 0L;
            if (X >= 9.2233720368547758E+18)
                return 0x7fffffffffffffffL;
            if (X <= -9.2233720368547758E+18)
                return -9223372036854775808L;

            return (long)X;
        }

        /// <summary>
        /// Copy a floats bits to an integer
        /// </summary>
        /// 
        /// <param name="X">Float to convert</param>
        /// 
        /// <returns>The integer</returns>
        internal static int FloatToInt(float X)
        {
            float[] fa = new float[] { X };
            int[] ia = new int[1];
            Buffer.BlockCopy(fa, 0, ia, 0, 4);

            return ia[0];
        }

        /// <summary>
        /// Returns the highest order 1 bit in a number
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the highest order 1 bit in a number</returns>
        internal static int HighestOneBit(int X)
        {
            X |= URShift(X, 1);
            X |= URShift(X, 2);
            X |= URShift(X, 4);
            X |= URShift(X, 8);
            X |= URShift(X, 16);

            return X ^ URShift(X, 1);
        }

        /// <summary>
        /// Returns the highest order 1 bit in a number
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the highest order 1 bit in a number</returns>
        internal static long HighestOneBit(long X)
        {
            X |= URShift(X, 1);
            X |= URShift(X, 2);
            X |= URShift(X, 4);
            X |= URShift(X, 8);
            X |= URShift(X, 16);
            X |= URShift(X, 32);

            return X ^ URShift(X, 1);
        }

        /// <summary>
        /// Copy an integer to a byte array
        /// </summary>
        /// 
        /// <param name="X">Integer to copy</param>
        /// 
        /// <returns>The integer bytes</returns>
        internal static byte[] IntToBytes(int X)
        {
            int[] num = new int[1] { X };
            byte[] data = new byte[4];
            Buffer.BlockCopy(num, 0, data, 0, 4);

            return data;
        }

        /// <summary>
        /// Copy an array of integers to a byte array
        /// </summary>
        /// 
        /// <param name="X">Array of integers</param>
        /// 
        /// <returns>The integers bytes</returns>
        internal static byte[] IntsToBytes(int[] X)
        {
            byte[] data = new byte[X.Length * 4];
            Buffer.BlockCopy(X, 0, data, 0, X.Length * 4);

            return data;
        }

        /// <summary>
        /// Copy an integer bits to a float
        /// </summary>
        /// 
        /// <param name="X">Integer to copy</param>
        /// 
        /// <returns>The float</returns>
        internal static float IntToFloat(int X)
        {
            int[] ia = new int[] { X };
            float[] fa = new float[1];
            Buffer.BlockCopy(ia, 0, fa, 0, 4);

            return fa[0];
        }

        /// <summary>
        /// Returns the leading number of zero bits
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the number of leading zeros</returns>
        internal static int NumberOfLeadingZeros(int X)
        {
            X |= URShift(X, 1);
            X |= URShift(X, 2);
            X |= URShift(X, 4);
            X |= URShift(X, 8);
            X |= URShift(X, 16);

            return BitCount(~X);
        }

        /// <summary>
        /// Returns the leading number of zero bits
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the number of leading zeros</returns>
        internal static int NumberOfLeadingZeros(long X)
        {
            X |= URShift(X, 1);
            X |= URShift(X, 2);
            X |= URShift(X, 4);
            X |= URShift(X, 8);
            X |= URShift(X, 16);
            X |= URShift(X, 32);

            return BitCount(~X);
        }

        /// <summary>
        /// Returns the trailing number of zero bits
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the number of trailing zeros</returns>
        internal static int NumberOfTrailingZeros(int X)
        {
            return BitCount((X & -X) - 1);
        }

        /// <summary>
        /// Returns the trailing number of zero bits
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the number of trailing zeros</returns>
        internal static int NumberOfTrailingZeros(long X)
        {
            return BitCount((X & -X) - 1);
        }

        /// <summary>
        /// Parses the string argument as a signed decimal integer. 
        /// </summary>
        /// 
        /// <param name="S">A String containing the int representation to be parsed</param>
        /// 
        /// <returns>The integer value represented by the argument in decimal</returns>
        internal static int ParseInt(String S)
        {
            return ParseInt(S, 10);
        }

        /// <summary>
        /// Parses the string argument as a signed integer in the radix specified by the second argument. 
        /// </summary>
        /// 
        /// <param name="S">The String containing the integer representation to be parsed</param>
        /// <param name="Radix">The radix to be used while parsing</param>
        /// 
        /// <returns>The integer represented by the string argument in the specified radix</returns>
        internal static int ParseInt(String S, int Radix)
        {
            if (S == null)
                throw new FormatException("null");

            if (Radix < (int)CharConsts.MIN_RADIX)
                throw new FormatException("radix " + Radix + " less than Character.MIN_RADIX");

            if (Radix > (int)CharConsts.MAX_RADIX)
                throw new FormatException("radix " + Radix + " greater than Character.MAX_RADIX");

            int result = 0;
            bool negative = false;
            int i = 0, len = S.Length;
            int limit = -(int)IntConsts.MAX_VALUE;
            int multmin;
            int digit;

            if (len > 0)
            {
                char firstChar = CharUtils.CharAt(S, 0);
                if (firstChar < '0')
                { // Possible leading "+" or "-"
                    if (firstChar == '-')
                    {
                        negative = true;
                        limit = (int)IntConsts.MIN_VALUE;
                    }
                    else if (firstChar != '+')
                    {
                        throw new FormatException();
                    }

                    if (len == 1)
                        throw new FormatException("Cannot have lone + or -");

                    i++;
                }
                multmin = limit / Radix;
                while (i < len)
                {
                    // Accumulating negatively avoids surprises near MAX_VALUE
                    digit = (int)Char.GetNumericValue(CharUtils.CharAt(S, i++));
                    if (digit < 0)
                        throw new FormatException();
                    if (result < multmin)
                        throw new FormatException();

                    result *= Radix;
                    if (result < limit + digit)
                        throw new FormatException();

                    result -= digit;
                }
            }
            else
            {
                throw new FormatException();
            }

            return negative ? result : -result;
        }

        /// <summary>
        /// Read a short value (16 bits) from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">Stream containing the short value</param>
        /// 
        /// <returns>The Int16 value</returns>
        public static int ReadShort(System.IO.Stream InputStream)
        {
            return InputStream.ReadByte() * 256 + InputStream.ReadByte();
        }

        /// <summary>
        /// Reverse a byte array order and copy to an integer
        /// </summary>
        /// 
        /// <param name="Data">The byte array to reverse</param>
        /// 
        /// <returns>The reversed integer</returns>
        public static int ReverseBytes(byte[] Data)
        {
            // make a copy
            byte[] temp = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, temp, 0, Data.Length);
            // reverse and copy to int
            Array.Reverse(temp);
            int[] ret = new int[1];
            Buffer.BlockCopy(Data, 0, ret, 0, Data.Length);

            return ret[0];
        }

        /// <summary>
        /// Reverse the byte order of an integer
        /// </summary>
        /// 
        /// <param name="Value">The integer value to reverse</param>
        /// 
        /// <returns>The reversed integer</returns>
        public static int ReverseBytes(int Value)
        {
            int[] data = new int[] { Value };
            byte[] ret = new byte[4];

            Buffer.BlockCopy(data, 0, ret, 0, 4);
            Array.Reverse(ret);
            Buffer.BlockCopy(ret, 0, data, 0, 4);

            return data[0];
        }

        /// <summary>
        /// Returns the value obtained by reversing the order of the bits in the 
        /// two's complement binary representation of the specified int value
        /// </summary>
        /// 
        /// <param name="X">The value to be reversed</param>
        /// 
        /// <returns>The value obtained by reversing order of the bits in the specified int value</returns>
        internal static int ReverseInt(int X)
        {
            X = (int)((uint)(X & 0x55555555) << 1 | (uint)(X >> 1) & 0x55555555);
            X = (int)((uint)(X & 0x33333333) << 2 | (uint)(X >> 2) & 0x33333333);
            X = (int)((uint)(X & 0x0f0f0f0f) << 4 | (uint)(X >> 4) & 0x0f0f0f0f);
            X = (X << 24) | ((X & 0xff00) << 8) | ((X >> 8) & 0xff00) | (X >> 24);

            return X;
        }

        /// <summary>
        /// Returns the signum function of the specified long value. 
        /// <para>The return value is -1 if the specified value is negative;
        /// 0 if the specified value is zero; and 1 if the specified value is positive.</para>
        /// </summary>
        /// 
        /// <param name="X">The value whose signum is to be computed</param>
        /// 
        /// <returns>The signum function of the specified long value</returns>
        internal static int Signum(long X)
        {
            return (int)(((uint)X >> 63) | ((uint)-X >> 63));
        }

        /// <summary>
        /// Convert an integer to a string
        /// </summary>
        /// 
        /// <param name="X">The integer to convert</param>
        /// <returns>Returns the integer as a string</returns>
        internal static string ToString(int X)
        {
            return X.ToString();
        }

        /// <summary>
        /// Convert a long integer to a string
        /// </summary>
        /// 
        /// <param name="X">The long integer to convert</param>
        /// <returns>Returns the long integer as a string</returns>
        internal static string ToString(long X)
        {
            return X.ToString();
        }

        /// <summary>
        /// Operates an unsigned right shift on the given integer by the number of bits specified
        /// </summary>
        /// 
        /// <param name="X">The number to shift</param>
        /// <param name="NumBits">The number of bits to shift the given number</param>
        /// 
        /// <returns>
        /// Returns an <see cref="System.Int32">int</see> representing the shifted number.
        /// </returns>
        internal static int URShift(int X, int NumBits)
        {
            if (X >= 0)
                return X >> NumBits;

            return (X >> NumBits) + (2 << ~NumBits);
        }

        /// <summary>
        /// Operates an unsigned right shift on the given integer by the number of bits specified
        /// </summary>
        /// 
        /// <param name="X">The number to shift</param>
        /// <param name="NumBits">The number of bits to shift the given number</param>
        /// 
        /// <returns>
        /// Returns an <see cref="System.Int64">long integer</see> representing the shifted number.
        /// </returns>
        internal static long URShift(long X, int NumBits)
        {
            if (X >= 0)
                return X >> NumBits;
            return (X >> NumBits) + (2L << ~NumBits);
        }
        #endregion
    }
}
