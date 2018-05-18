#region Directives
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// Compare arrays for equality; internal version
    /// <para>Security Change: 1.4B, all internal comparisons (hash, equals, etc..) are now done with this class</para>
    /// </summary>
    internal static class Compare
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
        public static bool IsEqual(BigDecimal[] A, BigDecimal[] B)
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
        public static bool IsEqual(BigInteger[] A, BigInteger[] B)
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
        public static bool IsEqual(byte[] A, byte[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(char[] A, char[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(short[] A, short[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(ushort[] A, ushort[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(int[] A, int[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(uint[] A, uint[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(long[] A, long[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(ulong[] A, ulong[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(float[] A, float[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
        public static bool IsEqual(double[] A, double[] B)
        {
            if (A == null && B != null || B == null && A != null)
                return false;
            else if (A == null && B == null)
                return true;

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
    }
}
