namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.Arithmetic
{
    internal static class FFT
    {
        public static void Add2(uint[] A, uint[] B, uint[] C, int Q)
        {
            for (int i = 0; i < A.Length; i++)
            {
                A[i] = B[i] + C[i];
                A[i] = Mod((int)A[i], Q);
            }
        }

        public static void Mul2(uint[] A, uint[] B, uint[] C, int Q)
        {
            for (int i = 0; i < A.Length; i++)
            {
                A[i] = B[i] * C[i];
                A[i] = Mod((int)A[i], Q);
            }
        }

        public static void MulAdd2(uint[] Result, uint[] L1, uint[] L2, uint[] L3, int Q)
        {
            for (int i = 0; i < Result.Length; i++)
            {
                Result[i] = L1[i] * L2[i];
                Result[i] = Result[i] + L3[i];
                Result[i] = Mod((int)Result[i], Q);
            }
        }

        public static void Sub2(uint[] A, uint[] B, uint[] C, int Q)
        {
            for (int i = 0; i < A.Length; i++)
            {
                A[i] = B[i] - C[i];
                A[i] = Mod((int)A[i], Q);
            }
        }

        public static uint Mod(int A, int Q)
        {
            int quotient, remainder;
            quotient = A / Q;

            if (A >= 0)
                remainder = A - quotient * Q;
            else
                remainder = (1 - quotient) * Q + A;

            return (uint)remainder;
        }
    }
}
