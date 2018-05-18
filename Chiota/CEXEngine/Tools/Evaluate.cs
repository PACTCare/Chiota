#region Directives
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// Compare arrays for equality
    /// <para>Security Change: 1.4B, all internal comparisons (hashing, equals..) are now done with the CEXEngine.Crypto.Common.Compare class.</para>
    /// </summary>
    public static class Evaluate
    {
        /// <summary>
        /// Returns true if condition is false
        /// </summary>
        /// 
        /// <param name="B">Test variable</param>
        /// 
        /// <returns>State</returns>
        public static bool False(bool B)
        {
            if (B)
                return false;

            return true;
        }

        /// <summary>
        /// Returns true if condition is true
        /// </summary>
        /// 
        /// <param name="B">Test variable</param>
        /// 
        /// <returns>State</returns>
        public static bool True(bool B)
        {
            if (!B)
                return false;

            return true;
        }

        /// <summary>
        /// Compare BigDecimal arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(BigDecimal[] A, BigDecimal[] B)
        {
            for (int i = 0; i < A.Length; i++)
            {
                if (!A[i].Equals(B[i]))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Compare BigInteger arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(BigInteger[] A, BigInteger[] B)
        {
            for (int i = 0; i < A.Length; i++)
            {
                if (!A[i].Equals(B[i]))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Compare Byte arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(byte[] A, byte[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                {
                    //int x = A[i];
                    //int y = B[i];
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Compare Char arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(char[] A, char[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare short Int16 arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(short[] A, short[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare int arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(int[] A, int[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare long arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(long[] A, long[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare float arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(float[] A, float[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare double arrays for equality
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(double[] A, double[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Check if a byte array contains a sequence of values
        /// </summary>
        /// 
        /// <param name="Data">Primary array</param>
        /// <param name="Value">Search item</param>
        /// 
        /// <returns>The array contains the value</returns>
        public static bool Contains(byte[] Data, byte[] Value)
        {
            if (Data.Length < Value.Length)
                return false;

            for (int i = 0; i < Data.Length; i++)
            {
                if (Data[i] == Value[0])
                {
                    if (Value.Length > Data.Length - i)
                        return false;

                    for (int j = 0; j < Value.Length; j++)
                    {
                        if (Data[i + j] != Value[j])
                            break;
                        else if (j == Value.Length - 1)
                            return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Check if a char array contains a sequence of values
        /// </summary>
        /// 
        /// <param name="Data">Primary array</param>
        /// <param name="Value">Search item</param>
        /// 
        /// <returns>The array contains the value</returns>
        public static bool Contains(char[] Data, char[] Value)
        {
            if (Data.Length < Value.Length)
                return false;

            for (int i = 0; i < Data.Length; i++)
            {
                if (Data[i] == Value[0])
                {
                    if (Value.Length > Data.Length - i)
                        return false;

                    for (int j = 0; j < Value.Length; j++)
                    {
                        if (Data[i + j] != Value[j])
                            break;
                        else if (j == Value.Length - 1)
                            return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Check if a Int16 array contains a sequence of values
        /// </summary>
        /// 
        /// <param name="Data">Primary array</param>
        /// <param name="Value">Search item</param>
        /// 
        /// <returns>The array contains the value</returns>
        public static bool Contains(short[] Data, short[] Value)
        {
            if (Data.Length < Value.Length)
                return false;

            for (int i = 0; i < Data.Length; i++)
            {
                if (Data[i] == Value[0])
                {
                    if (Value.Length > Data.Length - i)
                        return false;

                    for (int j = 0; j < Value.Length; j++)
                    {
                        if (Data[i + j] != Value[j])
                            break;
                        else if (j == Value.Length - 1)
                            return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Check if a int array contains a sequence of values
        /// </summary>
        /// 
        /// <param name="Data">Primary array</param>
        /// <param name="Value">Search item</param>
        /// 
        /// <returns>The array contains the value</returns>
        public static bool Contains(int[] Data, int[] Value)
        {
            if (Data.Length < Value.Length)
                return false;

            for (int i = 0; i < Data.Length; i++)
            {
                if (Data[i] == Value[0])
                {
                    if (Value.Length > Data.Length - i)
                        return false;

                    for (int j = 0; j < Value.Length; j++)
                    {
                        if (Data[i + j] != Value[j])
                            break;
                        else if (j == Value.Length - 1)
                            return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Check if a long array contains a sequence of values
        /// </summary>
        /// 
        /// <param name="Data">Primary array</param>
        /// <param name="Value">Search item</param>
        /// 
        /// <returns>The array contains the value</returns>
        public static bool Contains(long[] Data, long[] Value)
        {
            if (Data.Length < Value.Length)
                return false;

            for (int i = 0; i < Data.Length; i++)
            {
                if (Data[i] == Value[0])
                {
                    if (Value.Length > Data.Length - i)
                        return false;

                    for (int j = 0; j < Value.Length; j++)
                    {
                        if (Data[i + j] != Value[j])
                            break;
                        else if (j == Value.Length - 1)
                            return true;
                    }
                }
            }

            return false;
        }
    }
}
