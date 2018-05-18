#region Directives
using System;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// This is a utility class containing data type conversions using big-endian byte order
    /// </summary>
    internal static class BigEndian
    {
        /// <summary>
        /// Convert an integer to an octet string of length 4 according to IEEE 1363, Section 5.5.3
        /// </summary>
        /// <param name="Input">The integer to convert</param>
        /// 
        /// <returns>The converted integer</returns>
        public static byte[] IntToOctets(int Input)
        {
            byte[] result = new byte[4];
            result[0] = (byte)(Input >> 24);
            result[1] = (byte)(Input >> 16);
            result[2] = (byte)(Input >> 8);
            result[3] = (byte)Input;

            return result;
        }

        /// <summary>
        /// Convert an integer to an octet string according to IEEE 1363, Section 5.5.3. Length checking is performed
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Length">The desired length of the octet string</param>
        /// 
        /// <returns>Returns an octet string of length <c>OctLength</c> representing the integer <c>X</c>, or <c>null</c> if the integer is negative</returns>
        public static byte[] IntToOctets(int Input, int Length)
        {
            if (Input < 0)
                return null;
            
            int octL = CeilLog256(Input);
            if (octL > Length)
                throw new ArithmeticException("BigEndianConversions: Cannot encode given integer into specified number of octets!");
            
            byte[] result = new byte[Length];
            for (int i = Length - 1; i >= Length - octL; i--)
                result[i] = (byte)(Input >> (8 * (Length - 1 - i)));
            
            return result;
        }

        private static int CeilLog256(int X)
        {
            if (X == 0)
                return 1;
            int m;
            if (X < 0)
                m = -X;
            else
                m = X;

            int d = 0;
            while (m > 0)
            {
                d++;
                m = IntUtils.URShift(m, 8);
            }

            return d;
        }

        /// <summary>
        /// Convert an integer to an octet string of length 4 according to IEEE 1363, Section 5.5.3
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Output">The byte array holding the output</param>
        /// <param name="OutOffset">The starting offset in the output array</param>
        public static void IntToOctets(int Input, byte[] Output, int OutOffset)
        {
            Output[OutOffset++] = (byte)(Input >> 24);
            Output[OutOffset++] = (byte)(Input >> 16);
            Output[OutOffset++] = (byte)(Input >> 8);
            Output[OutOffset] = (byte)Input;
        }

        /// <summary>
        /// Convert an integer to an octet string of length 8 according to IEEE 1363, Section 5.5.3
        /// </summary>
        /// 
        /// <param name="Input">he integer to convert</param>
        /// 
        /// <returns>The converted long integer</returns>
        public static byte[] LongToOctets(long Input)
        {
            byte[] output = new byte[8];
            output[0] = (byte)(Input >> 56);
            output[1] = (byte)(Input >> 48);
            output[2] = (byte)(Input >> 40);
            output[3] = (byte)(Input >> 32);
            output[4] = (byte)(Input >> 24);
            output[5] = (byte)(Input >> 16);
            output[6] = (byte)(Input >> 8);
            output[7] = (byte)Input;

            return output;
        }

        /// <summary>
        /// Convert an integer to an octet string of the specified length according to IEEE 1363, Section 5.5.3.
        /// <para>No length checking is performed (i.e., if the integer cannot be encoded into <c>length</c> octets, it is truncated).</para>
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Output">The byte array holding the output</param>
        /// <param name="OutOffset">The starting offset in the output array</param>
        /// <param name="Length">The length of the encoding</param>
        public static void IntToOctets(int Input, byte[] Output, int OutOffset, int Length)
        {
            for (int i = Length - 1; i >= 0; i--)
                Output[OutOffset + i] = (byte)(Input >> (8 * (Length - 1 - i)));
        }

        /// <summary>
        /// Convert an integer to an octet string of length 8 according to IEEE 1363, Section 5.5.3
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Output">The byte array holding the output</param>
        /// <param name="OutOffset">The starting offset in the output array</param>
        public static void LongToOctets(long Input, byte[] Output, int OutOffset)
        {
            Output[OutOffset++] = (byte)(Input >> 56);
            Output[OutOffset++] = (byte)(Input >> 48);
            Output[OutOffset++] = (byte)(Input >> 40);
            Output[OutOffset++] = (byte)(Input >> 32);
            Output[OutOffset++] = (byte)(Input >> 24);
            Output[OutOffset++] = (byte)(Input >> 16);
            Output[OutOffset++] = (byte)(Input >> 8);
            Output[OutOffset] = (byte)Input;
        }

        /// <summary>
        /// Convert an octet string to an integer according to IEEE 1363, Section 5.5.3
        /// </summary>
        /// 
        /// <param name="Input">he byte array holding the octet string</param>
        /// 
        /// <returns>Returns an integer representing the octet string <c>Input</c>, or <c>0</c> if the represented integer is negative or too large or the byte array is empty</returns>
        public static int OctetsToInt(byte[] Input)
        {
            if (Input.Length > 4)
                throw new ArithmeticException("BigEndianConversions: Invalid input length!");
            
            if (Input.Length == 0)
                return 0;
            
            int result = 0;
            for (int j = 0; j < Input.Length; j++)
                result |= (Input[j] & 0xff) << (8 * (Input.Length - 1 - j));
            
            return result;
        }

        /// <summary>
        /// Convert a byte array of length 4 beginning at <c>offset</c> into an integer
        /// </summary>
        /// 
        /// <param name="Input">The byte array</param>
        /// <param name="InOffset">The offset into the byte array</param>
        /// <returns>The resulting integer</returns>
        public static int OctetsToInt(byte[] Input, int InOffset)
        {
            return ((Input[InOffset++] & 0xff) << 24) |
                ((Input[InOffset++] & 0xff) << 16) |
                ((Input[InOffset++] & 0xff) << 8) |
                Input[InOffset] & 0xff;
        }

        /// <summary>
        /// Convert an octet string to an integer according to IEEE 1363, Section 5.5.3
        /// </summary>
        /// 
        /// <param name="Input">The byte array holding the octet string</param>
        /// <param name="InOffset">The offset in the input byte array where the octet string starts</param>
        /// <param name="Length">The length of the encoded integer</param>
        /// 
        /// <returns>Returns an integer representing the octet string <c>bytes</c>, or <c>0</c> if the represented integer is negative or too large or the byte array is empty</returns>
        public static int OctetsToInt(byte[] Input, int InOffset, int Length)
        {
            if ((Input.Length == 0) || Input.Length < InOffset + Length - 1)
                return 0;
            
            int result = 0;
            for (int j = 0; j < Length; j++)
                result |= (Input[InOffset + j] & 0xff) << (8 * (Length - j - 1));
            
            return result;
        }

        /// <summary>
        /// Convert a byte array of length 8 beginning at <c>inOff</c> into a long integer
        /// </summary>
        /// 
        /// <param name="Input">The byte array</param>
        /// <param name="InOffset">The offset into the byte array</param>
        /// 
        /// <returns>The resulting long integer</returns>
        public static long OctetsToLong(byte[] Input, int InOffset)
        {
            return (((long)Input[InOffset++] & 0xff) << 56) |
                (((long)Input[InOffset++] & 0xff) << 48) |
                (((long)Input[InOffset++] & 0xff) << 40) |
                (((long)Input[InOffset++] & 0xff) << 32) |
                (((long)Input[InOffset++] & 0xff) << 24) |
                (((long)Input[InOffset++] & 0xff) << 16) |
                (((long)Input[InOffset++] & 0xff) << 8) |
                ((long)Input[InOffset] & 0xff);
        }

        /// <summary>
        /// Convert an int array into a byte array
        /// </summary>
        /// 
        /// <param name="Input">The int array</param>
        /// 
        /// <returns>The converted array</returns>
        public static byte[] ToByteArray(int[] Input)
        {
            byte[] result = new byte[Input.Length << 2];
            for (int i = 0; i < Input.Length; i++)
                IntToOctets(Input[i], result, i << 2);
            
            return result;
        }

        /// <summary>
        /// Convert an int array into a byte array of the specified length.
        /// <para>No length checking is performed (i.e., if the last integer cannot be encoded into <c>length % 4</c> octets, it is truncated).</para>
        /// </summary>
        /// 
        /// <param name="Input">The int array</param>
        /// <param name="Length">The length of the converted array</param>
        /// 
        /// <returns>The converted array</returns>
        public static byte[] ToByteArray(int[] Input, int Length)
        {
            int intLen = Input.Length;
            byte[] result = new byte[Length];
            int index = 0;

            for (int i = 0; i <= intLen - 2; i++, index += 4)
                IntToOctets(Input[i], result, index);
            IntToOctets(Input[intLen - 1], result, index, Length - index);

            return result;
        }

        /// <summary>
        /// Convert a byte array into an int array
        /// </summary>
        /// 
        /// <param name="Input">The byte array</param>
        /// 
        /// <returns>The converted array</returns>
        public static int[] ToIntArray(byte[] Input)
        {
            int intLen = (Input.Length + 3) / 4;
            int lastLen = Input.Length & 0x03;
            int[] result = new int[intLen];

            int index = 0;
            for (int i = 0; i <= intLen - 2; i++, index += 4)
                result[i] = OctetsToInt(Input, index);

            if (lastLen != 0)
                result[intLen - 1] = OctetsToInt(Input, index, lastLen);
            else
                result[intLen - 1] = OctetsToInt(Input, index);

            return result;
        }
    }
}
