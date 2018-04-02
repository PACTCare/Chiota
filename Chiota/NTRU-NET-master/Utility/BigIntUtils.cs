#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// This class is a utility class for manipulating <see cref="BigInteger"/> arrays
    /// </summary>
    public static class BigIntUtils
    {
        /// <summary>
        /// Checks if two <see cref="BigInteger"/> arrays contain the same entries
        /// </summary>
        /// 
        /// <param name="A">The first BigInteger array</param>
        /// <param name="B">The second BigInteger array</param>
        /// 
        /// <returns>Returns A[] is equal to B[]</returns>
        public static bool Equals(BigInteger[] A, BigInteger[] B)
        {
            int flag = 0;

            if (A.Length != B.Length)
                return false;
            
            for (int i = 0; i < A.Length; i++)
                flag |= A[i].CompareTo(B[i]);
            
            return flag == 0;
        }

        /// <summary>
        /// Fill the given <see cref="BigInteger"/> array with the given value
        /// </summary>
        /// 
        /// <param name="A">The BigInteger array</param>
        /// <param name="Value">The BigInteger value</param>
        public static void Fill(BigInteger[] A, BigInteger Value)
        {
            for (int i = A.Length - 1; i >= 0; i--)
                A[i] = Value;
        }

        /// <summary>
        /// Generates a subarray of a given <see cref="BigInteger"/> array
        /// </summary>
        /// 
        /// <param name="Input">The input BigInteger array</param>
        /// <param name="Start">The start index</param>
        /// <param name="End">The end index</param>
        /// 
        /// <returns>Returns a subarray of <c>input</c>, ranging from <c>Start</c> to <c>End</c></returns>
        public static BigInteger[] SubArray(BigInteger[] Input, int Start, int End)
        {
            BigInteger[] result = new BigInteger[End - Start];
            Array.Copy(Input, Start, result, 0, End - Start);

            return result;
        }

        /// <summary>
        /// Converts a <see cref="BigInteger"/> array into an integer array
        /// </summary>
        /// 
        /// <param name="Input">The BigInteger array</param>
        /// 
        /// <returns>Returns the integer array</returns>
        public static int[] ToIntArray(BigInteger[] Input)
        {
            int[] result = new int[Input.Length];
            for (int i = 0; i < Input.Length; i++)
                result[i] = Input[i].ToInt32();
            
            return result;
        }

        /// <summary>
        /// Converts a BigInteger array into an integer array, reducing all BigIntegers mod q
        /// </summary>
        /// 
        /// <param name="Q">The modulus</param>
        /// <param name="Input">The BigInteger array</param>
        /// 
        /// <returns>Returns the integer array</returns>
        public static int[] ToIntArrayModQ(int Q, BigInteger[] Input)
        {
            BigInteger bq = BigInteger.ValueOf(Q);
            int[] result = new int[Input.Length];

            for (int i = 0; i < Input.Length; i++)
                result[i] = Input[i].Mod(bq).ToInt32();
            
            return result;
        }

        /// <summary>
        /// Return the value of <see cref="BigInteger"/> as a byte array
        /// </summary>
        /// 
        /// <param name="Value">The <c>BigInteger</c> value to be converted to a byte array</param>
        /// 
        /// <returns>Returns the value <c>big</c> as byte array</returns>
        /// 
        /// <remarks>
        /// <para>Although BigInteger has such a method, it uses an extra bit to indicate the sign of the number.
        /// For elliptic curve cryptography, the numbers usually are positive.
        /// Thus, this helper method returns a byte array of minimal length, ignoring the sign of the number.</para>
        /// </remarks>
        public static byte[] ToMinimalByteArray(BigInteger Value)
        {
            byte[] valBytes = Value.ToByteArray();
            if ((valBytes.Length == 1) || (Value.BitLength & 0x07) != 0)
                return valBytes;

            byte[] result = new byte[Value.BitLength >> 3];
            Array.Copy(valBytes, 1, result, 0, result.Length);

            return result;
        }
    }
}
