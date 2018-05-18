#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// An integer utilities class
    /// </summary>
    internal static class IntUtils
    {
        #region Constants
        public static long INFLATED = long.MinValue;
        public static double DOUBLE_MAX = double.MaxValue;
        public static double NEGATIVE_INFINITY = -1.0 / 0.0;
        public static double NaN = 0.0d / 0.0;
        public static double POSITIVE_INFINITY = 1.0 / 0.0;
        public static long SIGNIF_BIT_MASK = 0x000FFFFFFFFFFFFFL;
        public static long SIGN_BIT_MASK = unchecked((long)0x8000000000000000L);
        #endregion

        #region Enums
        public enum CharConsts : int
        {
            MIN_RADIX = 2,
            MAX_RADIX = 36
        }

        public enum DoubleConsts : int
        {
            EXP_BIAS = 1023,
            SIZE = 64,
            MAX_EXPONENT = 1023,
            MIN_EXPONENT = -1022,
            SIGNIFICAND_WIDTH = 53
        }

        public enum FloatConsts : int
        {
            EXP_BIAS = 127,
            MAX_EXPONENT = 127,
            MIN_EXPONENT = -126,
            SIGN_BIT_MASK = unchecked((int)0x80000000),
            SIGNIF_BIT_MASK = 0x007FFFFF,
            SIGNIFICAND_WIDTH = 24,
            SIZE = 32
        }

        public enum IntConsts : int
        {
            MIN_VALUE = unchecked((int)0x80000000),
            MAX_VALUE = 0x7fffffff,
            SIZE = 32
        }
        public enum LongConsts : long
        {
            SIZE = 64,
            MIN_VALUE = unchecked((long)0x8000000000000000L),
            MAX_VALUE = 0x7fffffffffffffffL
        }
        #endregion

        #region public Methods
        // Different computer architectures store data using different byte orders. "Big-endian"
        // means the most significant byte is on the left end of a word. "Little-endian" means the 
        // most significant byte is on the right end of a word. i.e.: 
        // BE: uint(block[3]) | (uint(block[2]) << 8) | (uint(block[1]) << 16) | (uint(block[0]) << 24)
        // LE: uint(block[0]) | (uint(block[1]) << 8) | (uint(block[2]) << 16) | (uint(block[3]) << 24)

        // ** Big Endian word32 and dword ** //

        /// <summary>
        /// Convert a Big Endian 32 bit word to bytes
        /// </summary>
        /// 
        /// <param name="Word">The 32 bit word</param>
        /// <param name="Block">The destination bytes</param>
        /// <param name="Offset">Offset within the destination array</param>
        public static void Be32ToBytes(uint Word, byte[] Block, int Offset)
	    {
		    Block[Offset + 3] = (byte)Word;
		    Block[Offset + 2] = (byte)(Word >> 8);
		    Block[Offset + 1] = (byte)(Word >> 16);
		    Block[Offset] = (byte)(Word >> 24);
	    }

        /// <summary>
        /// Convert a Big Endian 64 bit dword to bytes
        /// </summary>
        /// 
        /// <param name="DWord">The 64 bit word</param>
        /// <param name="Block">The destination bytes</param>
        /// <param name="Offset">Offset within the destination array</param>
        public static void Be64ToBytes(ulong DWord, byte[] Block, int Offset)
	    {
		    Block[Offset + 7] = (byte)DWord;
		    Block[Offset + 6] = (byte)(DWord >> 8);
		    Block[Offset + 5] = (byte)(DWord >> 16);
		    Block[Offset + 4] = (byte)(DWord >> 24);
		    Block[Offset + 3] = (byte)(DWord >> 32);
		    Block[Offset + 2] = (byte)(DWord >> 40);
		    Block[Offset + 1] = (byte)(DWord >> 48);
		    Block[Offset] = (byte)(DWord >> 56);
	    }

        /// <summary>
        /// Convert a byte array to a Big Endian 32 bit word
        /// </summary>
        /// 
        /// <param name="Block">The source byte array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <returns>A 32 bit word in Big Endian format</returns>
        public static uint BytesToBe32(byte[] Block, int InOffset)
	    {
		    return
			    ((uint)Block[InOffset] << 24) |
			    ((uint)Block[InOffset + 1] << 16) |
			    ((uint)Block[InOffset + 2] << 8) |
			    ((uint)Block[InOffset + 3]);
	    }

        /// <summary>
        /// Convert a byte array to a Big Endian 64 bit dword
        /// </summary>
        /// 
        /// <param name="Block">The source byte array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <returns>A 64 bit word in Big Endian format</returns>
        public static ulong BytesToBe64(byte[] Block, int InOffset)
	    {
		    return
			    ((ulong)Block[InOffset] << 56) |
			    ((ulong)Block[InOffset + 1] << 48) |
			    ((ulong)Block[InOffset + 2] << 40) |
			    ((ulong)Block[InOffset + 3] << 32) |
			    ((ulong)Block[InOffset + 4] << 24) |
			    ((ulong)Block[InOffset + 5] << 16) |
			    ((ulong)Block[InOffset + 6] << 8) |
			    ((ulong)Block[InOffset + 7]);
	    }

	    // ** Little Endian ** //

        /// <summary>
        /// Convert a Little Endian 32 bit word to bytes
        /// </summary>
        /// 
        /// <param name="Word">The 32 bit word</param>
        /// <param name="Block">The destination bytes</param>
        /// <param name="Offset">Offset within the destination block</param>
        public static void Le32ToBytes(uint Word, byte[] Block, int Offset)
	    {
		    Block[Offset] = (byte)Word;
		    Block[Offset + 1] = (byte)(Word >> 8);
		    Block[Offset + 2] = (byte)(Word >> 16);
		    Block[Offset + 3] = (byte)(Word >> 24);
	    }

        /// <summary>
        /// Convert a Little Endian 64 bit dword to bytes
        /// </summary>
        /// 
        /// <param name="DWord">The 64 bit word</param>
        /// <param name="Block">The destination bytes</param>
        /// <param name="Offset">Offset within the destination block</param>
        public static void Le64ToBytes(ulong DWord, byte[] Block, int Offset)
	    {
		    Block[Offset] = (byte)DWord;
		    Block[Offset + 1] = (byte)(DWord >> 8);
		    Block[Offset + 2] = (byte)(DWord >> 16);
		    Block[Offset + 3] = (byte)(DWord >> 24);
		    Block[Offset + 4] = (byte)(DWord >> 32);
		    Block[Offset + 5] = (byte)(DWord >> 40);
		    Block[Offset + 6] = (byte)(DWord >> 48);
		    Block[Offset + 7] = (byte)(DWord >> 56);
	    }

        public static void Le256ToBlock(uint[] Input, byte[] Output, int OutOffset)
        {
            Le32ToBytes(Input[0], Output, OutOffset);
            Le32ToBytes(Input[1], Output, OutOffset + 4);
            Le32ToBytes(Input[2], Output, OutOffset + 8);
            Le32ToBytes(Input[3], Output, OutOffset + 12);
            Le32ToBytes(Input[4], Output, OutOffset + 16);
            Le32ToBytes(Input[5], Output, OutOffset + 20);
            Le32ToBytes(Input[6], Output, OutOffset + 24);
            Le32ToBytes(Input[7], Output, OutOffset + 28);
        }

        public static void Le512ToBlock(ulong[] Input, byte[] Output, int OutOffset)
        {
            Le64ToBytes(Input[0], Output, OutOffset);
            Le64ToBytes(Input[1], Output, OutOffset + 8);
            Le64ToBytes(Input[2], Output, OutOffset + 16);
            Le64ToBytes(Input[3], Output, OutOffset + 24);
            Le64ToBytes(Input[4], Output, OutOffset + 32);
            Le64ToBytes(Input[5], Output, OutOffset + 40);
            Le64ToBytes(Input[6], Output, OutOffset + 48);
            Le64ToBytes(Input[7], Output, OutOffset + 56);
        }

        /// <summary>
        /// Convert a byte array to a Little Endian 32 bit word
        /// </summary>
        /// 
        /// <param name="Block">The source byte array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <returns>A 32 bit word in Little Endian format</returns>
        public static uint BytesToLe32(byte[] Block, int InOffset)
	    {
		    return
			    ((uint)Block[InOffset] |
			    ((uint)Block[InOffset + 1] << 8) |
			    ((uint)Block[InOffset + 2] << 16) |
			    ((uint)Block[InOffset + 3] << 24));
	    }

        /// <summary>
        /// Convert a byte array to a Little Endian 64 bit dword
        /// </summary>
        /// 
        /// <param name="Block">The source byte array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <returns>A 64 bit word in Little Endian format</returns>
        public static ulong BytesToLe64(byte[] Block, int InOffset)
	    {
		    return
			    ((ulong)Block[InOffset] |
			    ((ulong)Block[InOffset + 1] << 8) |
			    ((ulong)Block[InOffset + 2] << 16) |
			    ((ulong)Block[InOffset + 3] << 24) |
			    ((ulong)Block[InOffset + 4] << 32) |
			    ((ulong)Block[InOffset + 5] << 40) |
			    ((ulong)Block[InOffset + 6] << 48) |
			    ((ulong)Block[InOffset + 7] << 56));
	    }

        /// <summary>
        /// Returns the number of one-bits in the two's complement binary 
        /// representation of the specified int value. 
        /// <para>This function is sometimes referred to as the population count.</para>
        /// </summary>
        /// 
        /// <param name="X">The value whose bits are to be counted</param>
        /// 
        /// <returns>The number of one-bits in the two's complement binary representation of the specified int value</returns>
        public static int BitCount(int X)
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
        public static int BitCount(long X)
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
        public static int[] DeepCopy(int[] A)
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
        public static long DoubleToLong(double X)
        {
            #pragma warning disable 1718
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
        public static int FloatToInt(float X)
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
        public static int HighestOneBit(int X)
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
        public static long HighestOneBit(long X)
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
        public static byte[] IntToBytes(int X)
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
        public static byte[] IntsToBytes(int[] X)
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
        public static float IntToFloat(int X)
        {
            int[] ia = new int[] { X };
            float[] fa = new float[1];
            Buffer.BlockCopy(ia, 0, fa, 0, 4);

            return fa[0];
        }

        /// <summary>
        /// Copy a 64 bit integer to a byte array
        /// </summary>
        /// 
        /// <param name="X">Integer to copy</param>
        /// 
        /// <returns>The integer bytes</returns>
        public static byte[] LongToBytes(long X)
        {
            long[] num = new long[1] { X };
            byte[] data = new byte[8];
            Buffer.BlockCopy(num, 0, data, 0, 8);

            return data;
        }

        /// <summary>
        /// Copy an array of 64 bit integers to a byte array
        /// </summary>
        /// 
        /// <param name="X">Array of integers</param>
        /// 
        /// <returns>The integers bytes</returns>
        public static byte[] LongsToBytes(long[] X)
        {
            byte[] data = new byte[X.Length * 8];
            Buffer.BlockCopy(X, 0, data, 0, X.Length * 8);

            return data;
        }

        /// <summary>
        /// Copy a 64 bit integer bits to a double
        /// </summary>
        /// 
        /// <param name="X">Integer to copy</param>
        /// 
        /// <returns>The double</returns>
        public static double LongToDouble(long X)
        {
            long[] ia = new long[] { X };
            double[] fa = new double[1];
            Buffer.BlockCopy(ia, 0, fa, 0, 8);

            return fa[0];
        }

        /// <summary>
        /// Copy a 64 bit integer to a byte array
        /// </summary>
        /// 
        /// <param name="X">Integer to copy</param>
        /// 
        /// <returns>The integer bytes</returns>
        /// 
        public static byte[] ULongToBytes(ulong X)
        {
            ulong[] num = new ulong[1] { X };
            byte[] data = new byte[8];
            Buffer.BlockCopy(num, 0, data, 0, 8);

            return data;
        }
        /// <summary>
        /// Return the smaller of two values
        /// </summary>
        /// 
        /// <param name="A">The first comparison value</param>
        /// <param name="B">The second comparison value</param>
        /// 
        /// <returns>The smaller value</returns>
        public static int Min(int A, int B)
        {
            return ((A) < (B) ? (A) : (B));
        }

        /// <summary>
        /// Returns the leading number of zero bits
        /// </summary>
        /// 
        /// <param name="X">Number to test</param>
        /// 
        /// <returns>Returns the number of leading zeros</returns>
        public static int NumberOfLeadingZeros(int X)
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
        public static int NumberOfLeadingZeros(long X)
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
        public static int NumberOfTrailingZeros(int X)
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
        public static int NumberOfTrailingZeros(long X)
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
        public static int ParseInt(String S)
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
        public static int ParseInt(String S, int Radix)
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
        public static int ReverseInt(int X)
        {
            X = (int)((uint)(X & 0x55555555) << 1 | (uint)(X >> 1) & 0x55555555);
            X = (int)((uint)(X & 0x33333333) << 2 | (uint)(X >> 2) & 0x33333333);
            X = (int)((uint)(X & 0x0f0f0f0f) << 4 | (uint)(X >> 4) & 0x0f0f0f0f);
            X = (X << 24) | ((X & 0xff00) << 8) | ((X >> 8) & 0xff00) | (X >> 24);

            return X;
        }

        /// <summary>
        /// Rotate shift a 32 bit integer to the left
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The left shifted integer</returns>
        public static int RotateLeft(int Value, int Shift)
	    {
		    return (Value << Shift) | (Value >> (32 - Shift));
	    }

        /// <summary>
        /// Rotate shift an unsigned 32 bit integer to the left
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The left shifted integer</returns>
        public static uint RotateLeft(uint Value, int Shift)
        {
            return (Value << Shift) | (Value >> (32 - Shift));
        }

        /// <summary>
        /// Rotate shift a 64 bit integer to the left
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The left shifted integer</returns>
	    public static long RotateLeft(long Value, int Shift)
	    {
		    return (Value << Shift) | (Value >> (64 - Shift));
	    }

        /// <summary>
        /// Rotate shift an unsigned 64 bit integer to the left
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The left shifted integer</returns>
	    public static ulong RotateLeft(ulong Value, int Shift)
	    {
		    return (Value << Shift) | (Value >> (64 - Shift));
	    }

        /// <summary>
        /// Rotate shift an unsigned 32 bit integer to the right
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The right shifted integer</returns>
        public static int RotateRight(int Value, int Shift)
        {
            return (Value >> Shift) | (Value << (32 - Shift));
        }

        /// <summary>
        /// Rotate shift a 32 bit integer to the right
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The right shifted integer</returns>
	    public static uint RotateRight(uint Value, int Shift)
	    {
		    return (Value >> Shift) | (Value << (32 - Shift));
	    }

        /// <summary>
        /// Rotate shift a 64 bit integer to the right
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The right shifted integer</returns>
	    public static long RotateRight(long Value, int Shift)
	    {
		    return (Value >> Shift) | (Value << (64 - Shift));
	    }

        /// <summary>
        /// Rotate shift an unsigned 64 bit integer to the right
        /// </summary>
        /// 
        /// <param name="Value">The initial value</param>
        /// <param name="Shift">The number of bits to shift</param>
        /// 
        /// <returns>The right shifted integer</returns>
	    public static ulong RotateRight(ulong Value, int Shift)
	    {
		    return (Value >> Shift) | (Value << (64 - Shift));
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
        public static long Signum(long X)
        {
            return (long)(((ulong)X >> 63) | ((ulong)-X >> 63));
        }

        /// <summary>
        /// Convert an integer to a string
        /// </summary>
        /// 
        /// <param name="X">The integer to convert</param>
        /// <returns>Returns the integer as a string</returns>
        public static string ToString(int X)
        {
            return X.ToString();
        }

        /// <summary>
        /// Convert a long integer to a string
        /// </summary>
        /// 
        /// <param name="X">The long integer to convert</param>
        /// <returns>Returns the long integer as a string</returns>
        public static string ToString(long X)
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
        /// Returns an int representing the shifted number.
        /// </returns>
        public static int URShift(int X, int NumBits)
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
        /// Returns an long integer representing the shifted number.
        /// </returns>
        public static long URShift(long X, int NumBits)
        {
            if (X >= 0)
                return X >> NumBits;
            return (X >> NumBits) + (2L << ~NumBits);
        }

        /// <summary>
        /// Block XOR 4 bytes
        /// </summary>
        /// 
        /// <param name="Input">The source array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <param name="Output">The destination array</param>
        /// <param name="OutOffset">Offset within the destination array</param>
        public static void XOR32(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        Output[OutOffset] ^= Input[InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
        }

        /// <summary>
        /// Block XOR 8 bytes
        /// </summary>
        /// 
        /// <param name="Input">The source array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <param name="Output">The destination array</param>
        /// <param name="OutOffset">Offset within the destination array</param>
        public static void XOR64(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        Output[OutOffset] ^= Input[InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
        }

        /// <summary>
        /// Block XOR 16 bytes
        /// </summary>
        /// 
        /// <param name="Input">The source array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <param name="Output">The destination array</param>
        /// <param name="OutOffset">Offset within the destination array</param>
        public static void XOR128(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        Output[OutOffset] ^= Input[InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
        }

        /// <summary>
        /// Block XOR 32 bytes
        /// </summary>
        /// 
        /// <param name="Input">The source array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <param name="Output">The destination array</param>
        /// <param name="OutOffset">Offset within the destination array</param>
        public static void XOR256(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        Output[OutOffset] ^= Input[InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
	        Output[++OutOffset] ^= Input[++InOffset];
        }

        /// <summary>
        /// XOR contiguous 16 byte blocks in an array.
        /// <para>The array must be aligned to 16</para>
        /// </summary>
        /// 
        /// <param name="Input">The source array</param>
        /// <param name="InOffset">Offset within the source array</param>
        /// <param name="Output">The destination array</param>
        /// <param name="OutOffset">Offset within the destination array</param>
        /// <param name="Size">The number of (16 byte block aligned) bytes to process</param>
        public static void XORBLK(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Size)
        {
	        const int BLOCK = 16;
	        int ctr = 0;

	        do
	        {
		        XOR128(Input, InOffset + ctr, Output, OutOffset + ctr);
		        ctr += BLOCK;

	        } while (ctr != Size);
        }
        #endregion
    }
}
