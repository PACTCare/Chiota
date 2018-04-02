namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// This is a utility class containing data type conversions using little-endian byte order
    /// </summary>
    internal static class LittleEndian
    {
        /// <summary>
        /// Convert an integer to an octet string of length 4
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// 
        /// <returns>The converted integer</returns>
        public static byte[] IntToOctets(int Input)
        {
            byte[] result = new byte[4];
            result[0] = (byte)Input;
            result[1] = (byte)(Input >> 8);
            result[2] = (byte)(Input >> 16);
            result[3] = (byte)(Input >> 24);

            return result;
        }

        /// <summary>
        /// Convert an integer into a byte array beginning at the specified offset
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Output">The byte array to hold the result</param>
        /// <param name="Offset">The integer offset into the byte array</param>
        public static void IntToOctets(int Input, byte[] Output, int Offset)
        {
            Output[Offset++] = (byte)Input;
            Output[Offset++] = (byte)(Input >> 8);
            Output[Offset++] = (byte)(Input >> 16);
            Output[Offset++] = (byte)(Input >> 24);
        }

        /// <summary>
        /// Convert an integer to a byte array beginning at the specified offset.
        /// <para>No length checking is performed (i.e., if the integer cannot be encoded with <c>length</c> octets, it is truncated).</para>
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Output">The byte array to hold the result</param>
        /// <param name="Offset">The integer offset into the byte array</param>
        /// <param name="Length">The length of the encoding</param>
        public static void IntToOctets(int Input, byte[] Output, int Offset, int Length)
        {
            for (int i = Length - 1; i >= 0; i--)
                Output[Offset + i] = (byte)(Input >> (8 * i));
        }

        /// <summary>
        /// Convert an integer to a byte array of length 8
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// 
        /// <returns>The converted integer</returns>
        public static byte[] LongToOctets(long Input)
        {
            byte[] output = new byte[8];
            output[0] = (byte)Input;
            output[1] = (byte)(Input >> 8);
            output[2] = (byte)(Input >> 16);
            output[3] = (byte)(Input >> 24);
            output[4] = (byte)(Input >> 32);
            output[5] = (byte)(Input >> 40);
            output[6] = (byte)(Input >> 48);
            output[7] = (byte)(Input >> 56);

            return output;
        }

        /// <summary>
        /// Convert an integer to a byte array of length 8
        /// </summary>
        /// 
        /// <param name="Input">The integer to convert</param>
        /// <param name="Output">The offset in output array</param>
        /// <param name="Offset">The byte array holding the output</param>
        public static void LongToOctets(long Input, byte[] Output, int Offset)
        {
            Output[Offset++] = (byte)Input;
            Output[Offset++] = (byte)(Input >> 8);
            Output[Offset++] = (byte)(Input >> 16);
            Output[Offset++] = (byte)(Input >> 24);
            Output[Offset++] = (byte)(Input >> 32);
            Output[Offset++] = (byte)(Input >> 40);
            Output[Offset++] = (byte)(Input >> 48);
            Output[Offset] = (byte)(Input >> 56);
        }
        /// <summary>
        /// Convert an octet string of length 4 to an integer
        /// </summary>
        /// 
        /// <param name="Input">The byte array holding the octet string</param>
        /// 
        /// <returns>Returns an integer representing the octet string <c>Input</c></returns>
        public static int OctetsToInt(byte[] Input)
        {
            return (Input[0] & 0xff) |
                ((Input[1] & 0xff) << 8) |
                ((Input[2] & 0xff) << 16) |
                ((Input[3] & 0xff)) << 24;
        }

        /// <summary>
        /// Convert an byte array of length 4 beginning at <c>offset</c> into an integer
        /// </summary>
        /// 
        /// <param name="Input">The byte array</param>
        /// <param name="Offset">The offset into the byte array</param>
        /// 
        /// <returns>The resulting integer</returns>
        public static int OctetsToInt(byte[] Input, int Offset)
        {
            return (Input[Offset++] & 0xff) |
                ((Input[Offset++] & 0xff) << 8) |
                ((Input[Offset++] & 0xff) << 16) |
                ((Input[Offset] & 0xff) << 24);
        }

        /// <summary>
        /// Convert a byte array of the given length beginning at <c>offset</c> into an integer
        /// </summary>
        /// 
        /// <param name="Input">The byte array</param>
        /// <param name="Offset">The offset into the byte array</param>
        /// <param name="Length">The length of the encoding</param>
        /// 
        /// <returns>The resulting integer</returns>
        public static int OctetsToInt(byte[] Input, int Offset, int Length)
        {
            int result = 0;
            for (int i = Length - 1; i >= 0; i--)
                result |= (Input[Offset + i] & 0xff) << (8 * i);

            return result;
        }

        /// <summary>
        /// Convert a byte array of length 8 beginning at <c>inOff</c> into a long integer
        /// </summary>
        /// 
        /// <param name="Input">The byte array</param>
        /// <param name="Offset">The offset into the byte array</param>
        /// 
        /// <returns>The resulting long integer</returns>
        public static long OctetsToLong(byte[] Input, int Offset)
        {
            return ((long)Input[Offset++] & 0xff) |
                (((long)Input[Offset++] & 0xff) << 8) |
                (((long)Input[Offset++] & 0xff) << 16) |
                (((long)Input[Offset++] & 0xff) << 24) |
                (((long)Input[Offset++] & 0xff) << 32) |
                (((long)Input[Offset++] & 0xff) << 40) |
                (((long)Input[Offset++] & 0xff) << 48) |
                (((long)Input[Offset++] & 0xff) << 56);
        }

        /// <summary>
        /// Convert an int array to a byte array of the specified length.
        /// <para>No length checking is performed (i.e., if the last integer cannot be encoded with <c>length % 4</c> octets, it is truncated).</para>
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
        /// Convert a byte array to an int array
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
