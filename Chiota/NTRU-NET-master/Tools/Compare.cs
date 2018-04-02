#region Directives
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// Compare arrays for equality
    /// </summary>
    public static class Compare
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
        /// Compare BigDecimal Arrays
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
        /// Compare BigInteger Arrays
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
        /// Compare Byte Arrays
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
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare Char Arrays
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
        /// Compare short integer Arrays
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
        /// Compare Integer Arrays
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
        /// Compare Integer Arrays
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
        /// Compare float Arrays
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
        /// Compare double Arrays
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
        /// Compare Integer Arrays
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        [System.CLSCompliant(false)]
        public static bool AreEqual<T>(T[][] A, T[][] B)
        {
            int len = A.Length;

            if (len != B.Length)
                return false;

            while (len != 0)
            {
                --len;
                if (!AreEqual(A, B))
                    return false;
            }

            return true;
        }

    }
}
