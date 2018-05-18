#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// This class is a utility class for manipulating byte arrays
    /// </summary>
    internal static class ByteUtils
    {
        #region Fields
        private static char[] HEX_CHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        #endregion

        /// <summary>
        /// Return a clone of the given byte array (performs null check beforehand).
        /// </summary>
        /// 
        /// <param name="A">The array to clone</param>
        /// 
        /// <returns>Returns the clone of the given array, or <c>null</c> if the array is <c>null</c></returns>
        public static byte[] Clone(byte[] A)
        {
            if (A == null)
                return null;

            byte[] result = new byte[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

        /// <summary>
        /// Convert a 2-dimensional byte array into a 1-dimensional byte array by concatenating all entries
        /// </summary>
        /// 
        /// <param name="A">A 2-dimensional byte array</param>
        /// 
        /// <returns>Returns the concatenated input array</returns>
        public static byte[] Concatenate(byte[][] A)
        {
            int rowLen = A[0].Length;
            byte[] result = new byte[A.Length * rowLen];
            int index = 0;

            for (int i = 0; i < A.Length; i++)
            {
                Array.Copy(A[i], 0, result, index, rowLen);
                index += rowLen;
            }

            return result;
        }

        /// <summary>
        /// Concatenate two byte arrays. No null checks are performed
        /// </summary>
        /// 
        /// <param name="A">The first array</param>
        /// <param name="B">The second array</param>
        /// 
        /// <returns>Returns (x2||x1) (little-endian order, i.e. x1 is at lower memory addresses)</returns>
        public static byte[] Concatenate(byte[] A, byte[] B)
        {
            byte[] result = new byte[A.Length + B.Length];

            Array.Copy(A, 0, result, 0, A.Length);
            Array.Copy(B, 0, result, A.Length, B.Length);

            return result;
        }

        /// <summary>
        /// Computes a hashcode based on the contents of a one-dimensional byte array rather than its identity
        /// </summary>
        /// 
        /// <param name="A">The array to compute the hashcode of</param>
        /// 
        /// <returns>The hashcode</returns>
        public static int DeepHashCode(byte[] A)
        {
            int result = 1;
            for (int i = 0; i < A.Length; i++)
                result = 31 * result + A[i];

            return result;
        }

        /// <summary>
        /// Computes a hashcode based on the contents of a two-dimensional byte array rather than its identity
        /// </summary>
        /// 
        /// <param name="A">The array to compute the hashcode of</param>
        /// 
        /// <returns>The hashcode</returns>
        public static int DeepHashCode(byte[][] A)
        {
            int result = 1;
            for (int i = 0; i < A.Length; i++)
                result = 31 * result + DeepHashCode(A[i]);

            return result;
        }

        /// <summary>
        /// Computes a hashcode based on the contents of a three-dimensional byte array rather than its identity
        /// </summary>
        /// 
        /// <param name="A">The array to compute the hashcode of</param>
        /// 
        /// <returns>The hashcode</returns>
        public static int DeepHashCode(byte[][][] A)
        {
            int result = 1;
            for (int i = 0; i < A.Length; i++)
                result = 31 * result + DeepHashCode(A[i]);

            return result;
        }

        /// <summary>
        /// Compare two byte arrays (perform null checks beforehand).
        /// </summary>
        /// 
        /// <param name="A">The first byte array</param>
        /// <param name="B">The second byte array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(byte[] A, byte[] B)
        {
            if (A == null)
                return B == null;
            if (B == null)
                return false;

            if (A.Length != B.Length)
                return false;

            bool result = true;
            for (int i = A.Length - 1; i >= 0; i--)
                result &= A[i] == B[i];

            return result;
        }

        /// <summary>
        /// Compare two two-dimensional byte arrays; No null checks are performed.
        /// </summary>
        /// 
        /// <param name="A">The first byte array</param>
        /// <param name="B">The second byte array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(byte[][] A, byte[][] B)
        {
            if (A.Length != B.Length)
                return false;

            bool result = true;
            for (int i = A.Length - 1; i >= 0; i--)
                result &= ByteUtils.Equals(A[i], B[i]);

            return result;
        }

        /// <summary>
        /// Compare two three-dimensional byte arrays; No null checks are performed.
        /// </summary>
        /// 
        /// <param name="A">The first byte array</param>
        /// <param name="B">The second byte array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(byte[][][] A, byte[][][] B)
        {
            if (A.Length != B.Length)
                return false;

            bool result = true;
            for (int i = A.Length - 1; i >= 0; i--)
            {
                if (A[i].Length != B[i].Length)
                    return false;

                for (int j = A[i].Length - 1; j >= 0; j--)
                    result &= ByteUtils.Equals(A[i][j], B[i][j]);
            }

            return result;
        }

        /// <summary>
        /// Convert a string containing hexadecimal characters to a byte-array
        /// </summary>
        /// 
        /// <param name="S">A hex string</param>
        /// 
        /// <returns>Returns a byte array with the corresponding value</returns>
        public static byte[] FromHexString(String S)
        {
            char[] rawChars = S.ToUpper().ToCharArray();

            int hexChars = 0;
            for (int i = 0; i < rawChars.Length; i++)
            {
                if ((rawChars[i] >= '0' && rawChars[i] <= '9') || (rawChars[i] >= 'A' && rawChars[i] <= 'F'))
                    hexChars++;
            }

            byte[] byteString = new byte[(hexChars + 1) >> 1];

            int pos = hexChars & 1;

            for (int i = 0; i < rawChars.Length; i++)
            {
                if (rawChars[i] >= '0' && rawChars[i] <= '9')
                {
                    byteString[pos >> 1] <<= 4;
                    byteString[pos >> 1] |= (byte)(rawChars[i] - '0');
                }
                else if (rawChars[i] >= 'A' && rawChars[i] <= 'F')
                {
                    byteString[pos >> 1] <<= 4;
                    byteString[pos >> 1] |= (byte)(rawChars[i] - 'A' + 10);
                }
                else
                {
                    continue;
                }
                pos++;
            }

            return byteString;
        }

        /// <summary>
        /// Split a byte array <c>Input</c> into two arrays at <c>Index</c>.
        /// <para>The first array will have the lower <c>Index</c> bytes, the second one the higher <c>Input.Length - index</c> bytes.</para>
        /// </summary>
        /// 
        /// <param name="Input">The byte array to be split</param>
        /// <param name="Index">The index where the byte array is split</param>
        /// 
        /// <returns>Returns the split input array as an array of two byte arrays</returns>
        public static byte[][] Split(byte[] Input, int Index)
        {
            if (Index > Input.Length)
                throw new Exception();

            byte[][] result = new byte[2][];
            result[0] = new byte[Index];
            result[1] = new byte[Input.Length - Index];
            Array.Copy(Input, 0, result[0], 0, Index);
            Array.Copy(Input, Index, result[1], 0, Input.Length - Index);

            return result;
        }

        /// <summary>
        /// Generate a subarray of a given byte array
        /// </summary>
        /// 
        /// <param name="Input">The input byte array</param>
        /// <param name="Start">The start index</param>
        /// <param name="End">The end index</param>
        /// 
        /// <returns>Returns a subarray of <c>Input</c>, ranging from <c>Start</c> (inclusively) to <c>End</c> (exclusively)</returns>
        public static byte[] SubArray(byte[] Input, int Start, int End)
        {
            byte[] result = new byte[End - Start];
            Array.Copy(Input, Start, result, 0, End - Start);

            return result;
        }

        /// <summary>
        /// Generate a subarray of a given byte array
        /// </summary>
        /// 
        /// <param name="Input">The input byte array</param>
        /// <param name="Start">The start index</param>
        /// 
        /// <returns>Returns a subarray of <c>Input</c>, ranging from <c>Start</c> to the end of the array</returns>
        public static byte[] SubArray(byte[] Input, int Start)
        {
            return SubArray(Input, Start, Input.Length);
        }

        /// <summary>
        /// Convert a byte array to the corresponding bit string
        /// </summary>
        /// 
        /// <param name="Input">The byte array to be converted</param>
        /// 
        /// <returns>The corresponding bit string</returns>
        public static String ToBinaryString(byte[] Input)
        {
            String result = "";
            int i;

            for (i = 0; i < Input.Length; i++)
            {
                int e = Input[i];
                for (int ii = 0; ii < 8; ii++)
                {
                    int b = (IntUtils.URShift(e, ii)) & 1;
                    result += b;
                }

                if (i != Input.Length - 1)
                    result += " ";
            }

            return result;
        }

        /// <summary>
        /// Rewrite a byte array as a char array
        /// </summary>
        /// 
        /// <param name="Input">The byte array to convert</param>
        /// 
        /// <returns>Returns the bytes represented as a char array</returns>
        public static char[] ToCharArray(byte[] Input)
        {
            char[] result = new char[Input.Length];
            for (int i = 0; i < Input.Length; i++)
                result[i] = (char)Input[i];

            return result;
        }

        /// <summary>
        /// Convert a byte array to the corresponding hexstring
        /// </summary>
        /// 
        /// <param name="Input">The byte array to be converted</param>
        /// 
        /// <returns>Returns the corresponding hexstring</returns>
        public static String ToHexString(byte[] Input)
        {
            String result = "";

            for (int i = 0; i < Input.Length; i++)
            {
                result += HEX_CHARS[(IntUtils.URShift(Input[i], 4)) & 0x0f];
                result += HEX_CHARS[(Input[i]) & 0x0f];
            }

            return result;
        }

        /// <summary>
        /// Convert a byte array to the corresponding hex string
        /// </summary>
        /// 
        /// <param name="Input">The byte array to be converted</param>
        /// <param name="Prefix">The prefix to put at the beginning of the hex string</param>
        /// <param name="Seperator">A separator string</param>
        /// 
        /// <returns>The corresponding hex string</returns>
        public static String ToHexString(byte[] Input, String Prefix, String Seperator)
        {
            String result = Prefix;

            for (int i = 0; i < Input.Length; i++)
            {
                result += HEX_CHARS[(IntUtils.URShift(Input[i], 4)) & 0x0f];
                result += HEX_CHARS[(Input[i]) & 0x0f];
                if (i < Input.Length - 1)
                    result += Seperator;
            }

            return result;
        }

        /// <summary>
        /// Compute the bitwise XOR of two arrays of bytes.
        /// <para>The arrays have to be of same length. No length checking is performed.</para>
        /// </summary>
        /// 
        /// <param name="A">The first array</param>
        /// <param name="B">The second array</param>
        /// 
        /// <returns>Returns <c>A^B</c></returns>
        public static byte[] Xor(byte[] A, byte[] B)
        {
            byte[] output = new byte[A.Length];

            for (int i = A.Length - 1; i >= 0; i--)
                output[i] = (byte)(A[i] ^ B[i]);

            return output;
        }
    }
}
