#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Arithmetic
{
    /// <summary>
    /// An implementation of the <a href="http://en.wikipedia.org/wiki/Sch%C3%B6nhage%E2%80%93Strassen_algorithm">Schönhage-Strassen algorithm</a>
    /// for multiplying large numbers.
    /// </summary>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Arnold Schönhage und Volker Strassen: Schnelle Multiplikation großer Zahlen<cite>Schnelle Multiplikation großer Zahlen</cite>.</description></item>
    /// <item><description>Eine verstandliche Beschreibung des Schonhage-Strassen-Algorithmus<cite>Eine verstandliche Beschreibung des Schonhage-Strassen-Algorithmus</cite>.</description></item>
    /// </list>
    /// 
    /// Numbers are internally represented as <c>int</c> arrays; the <c>int</c>s are interpreted as unsigned numbers.
    /// </remarks>
    public sealed class SchonhageStrassen
    {
        #region Constants
        // min ints for Karatsuba
        private static int KARATSUBA_THRESHOLD = 32;   
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds two positive numbers (meaning they are interpreted as unsigned) modulo 2^2^N+1,
        /// where N is <c>A.Length*32/2</c>; in other words, n is half the number of bits in <c>A</c>.
        /// <para>Both input values are given as <c>int</c> arrays; they must be the same length.
        /// The result is returned in the first argument.</para>
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit; the length must be a power of 2</param>
        /// <param name="B">A number in base 2^32 starting with the lowest digit; the length must be a power of 2</param>
        public static void AddModFn(int[] A, int[] B)
        {
            bool carry = false;

            for (int i = 0; i < A.Length; i++)
            {
                int sum = A[i] + B[i];

                if (carry)
                    sum++;

                carry = (IntUtils.URShift(sum, 31) < IntUtils.URShift(A[i], 31) + IntUtils.URShift(B[i], 31));   // carry if signBit(sum) < signBit(a)+signBit(b)
                A[i] = sum;
            }

            // take a mod Fn by adding any remaining carry bit to the lowest bit;
            // since Fn â‰¡ 1 (mod 2^n), it suffices to add 1
            int j = 0;

            while (carry)
            {
                int sum = A[j] + 1;

                A[j] = sum;
                carry = sum == 0;
                j++;

                if (j >= A.Length)
                    j = 0;
            }
        }

        /// <summary>
        /// Adds two numbers, <c>A</c> and <c>B</c>, after shifting <c>B</c> by <c>numElements</c> elements.
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="B">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="NumElements">The shift amount in bits</param>
        /// 
        /// <remarks>
        /// Both numbers are given as <c>int</c> arrays and must be positive numbers (meaning they are interpreted as unsigned).
        /// The result is returned in the first argument. If any elements of B are shifted outside the valid range for <c>A</c>, they are dropped.
        /// </remarks>
        public static void AddShifted(int[] A, int[] B, int NumElements)
        {
            bool carry = false;
            int i = 0;

            while (i < Math.Min(B.Length, A.Length - NumElements))
            {
                int ai = A[i + NumElements];
                int sum = ai + B[i];

                if (carry)
                    sum++;

                carry = (IntUtils.URShift(sum, 31) < IntUtils.URShift(ai, 31) + IntUtils.URShift(B[i], 31));   // carry if signBit(sum) < signBit(a)+signBit(b)
                A[i + NumElements] = sum;
                i++;
            }

            while (carry)
            {
                A[i + NumElements]++;
                carry = A[i + NumElements] == 0;
                i++;
            }
        }

        /// <summary>
        /// Reads BitLenB bits from <c>B</c>, starting at array index 
        /// <c>StartB</c>, and copies them into <c>A</c>, starting at bit
        /// <c>BitLenA</c>. The result is returned in <c>A</c>.
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="BitLenA">Array A bit length</param>
        /// <param name="B">Array B</param>
        /// <param name="StartB">B starting position</param>
        /// <param name="BitLenB">Array B bit length</param>
        public static void AppendBits(int[] A, int BitLenA, int[] B, int StartB, int BitLenB)
        {
            int aIdx = BitLenA / 32;
            int bit32 = BitLenA % 32;

            for (int i = StartB; i < (StartB + BitLenB) / 32; i++)
            {
                if (bit32 > 0)
                {
                    A[aIdx] |= B[i] << bit32;
                    aIdx++;
                    A[aIdx] = IntUtils.URShift(B[i], (32 - bit32));
                }
                else
                {
                    A[aIdx] = B[i];
                    aIdx++;
                }
            }

            if (BitLenB % 32 > 0)
            {
                int bIdx = BitLenB / 32;
                int bi = B[StartB + bIdx];

                bi &= IntUtils.URShift(-1, (32 - BitLenB));
                A[aIdx] |= bi << bit32;

                if (bit32 + (BitLenB % 32) > 32)
                    A[aIdx + 1] = IntUtils.URShift(bi, (32 - bit32));
            }
        }

        /// <summary>
        /// Cyclicly shifts a number to the right modulo 2^2^n+1 and returns the result in a new array.
        /// <para>"Right" means towards the lower array indices and the lower bits; this is equivalent to
        /// a multiplication by <c>2^(-numBits) modulo 2^2^n+1</c>. The number n is <c>a.Length*32/2</c>; 
        /// in other words, n is half the number of bits in <c>A</c>.
        /// Both input values are given as <c>int</c> arrays; they must be the same length.
        /// </para>
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit; the length must be a power of 2</param>
        /// <param name="NumBits">The shift amount in bits</param>
        /// 
        /// <returns>The shifted number</returns>
        public static int[] CyclicShiftRight(int[] A, int NumBits)
        {
            int[] b = new int[A.Length];
            int numElements = NumBits / 32;

            Array.Copy(A, numElements, b, 0, A.Length - numElements);
            Array.Copy(A, 0, b, A.Length - numElements, numElements);
            NumBits = NumBits % 32;

            if (NumBits != 0)
            {
                int b0 = b[0];
                b[0] = IntUtils.URShift(b[0], NumBits);

                for (int i = 1; i < b.Length; i++)
                {
                    b[i - 1] |= b[i] << (32 - NumBits);
                    b[i] = IntUtils.URShift(b[i], NumBits);
                }

                b[b.Length - 1] |= b0 << (32 - NumBits);
            }
            return b;
        }

        /// <summary>
        /// Shifts a number to the left modulo 2^2^n+1 and returns the result in a new array.
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit; the length must be a power of 2</param>
        /// <param name="NumBits">The shift amount in bits</param>
        /// 
        /// <returns>The shifted number</returns>
        /// 
        /// <remarks>
        /// <para>"Left" means towards the lower array indices and the lower bits; this is equivalent to
        /// a multiplication by 2^numBits modulo 2^2^n+1.
        /// The number n is <c>a.Length*32/2</c>; in other words, n is half the number of bits in <c>A</c>.
        /// Both input values are given as <c>int</c> arrays; they must be the same length. The result is returned in the first argument.</para>
        /// </remarks>
        public static int[] CyclicShiftLeftBits(int[] A, int NumBits)
        {
            int[] b = CyclicShiftLeftElements(A, NumBits / 32);

            NumBits = NumBits % 32;
            if (NumBits != 0)
            {
                int bhi = b[b.Length - 1];
                b[b.Length - 1] <<= NumBits;

                for (int i = b.Length - 1; i > 0; i--)
                {
                    b[i] |= IntUtils.URShift(b[i - 1], (32 - NumBits));
                    b[i - 1] <<= NumBits;
                }

                b[0] |= IntUtils.URShift(bhi, (32 - NumBits));
            }
            return b;
        }

        /// <summary>
        /// Cyclicly shifts an array towards the higher indices by <c>numElements</c> elements and returns the result in a new array.
        /// </summary>
        /// 
        /// <param name="A">Input array</param>
        /// <param name="NumElements">The shift amount in bits</param>
        /// 
        /// <returns>The shifted number</returns>
        public static int[] CyclicShiftLeftElements(int[] A, int NumElements)
        {
            int[] b = new int[A.Length];

            Array.Copy(A, 0, b, NumElements, A.Length - NumElements);
            Array.Copy(A, A.Length - NumElements, b, 0, NumElements);

            return b;
        }

        /// <summary>
        /// Performs a Fermat Number Transform on an array whose elements are <c>int</c> arrays.<br/>
        /// </summary>
        /// <param name="A">Array to process</param>
        /// <param name="M">M Value</param>
        /// <param name="N">N Value</param>
        /// 
        /// <remarks>
        /// <para><c>A</c> is assumed to be the lower half of the full array and the upper half is assumed to be all zeros.
        /// The number of subarrays in <c>A</c> must be 2^n if m is even and 2^(n+1) if m is odd.<br/>
        /// Each subarray must be ceil(2^(n-1)) bits in length.<br/>
        /// * n must be equal to m/2-1.</para>
        /// <para><a href="http://en.wikipedia.org/wiki/Discrete_Fourier_transform_%28general%29#Number-theoretic_transform">Number-theoretic transform</a></para>
        /// 
        /// </remarks>
        public static void Dft(int[][] A, int M, int N)
        {
            bool even = M % 2 == 0;
            int len = A.Length;
            int v = 1;

            for (int slen = len / 2; slen > 0; slen /= 2)
            {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
                for (int j = 0; j < len; j += 2 * slen)
                {
                    int idx = j;
                    int x = GetDftExponent(N, v, idx + len, even);

                    for (int k = slen - 1; k >= 0; k--)
                    {
                        int[] d = CyclicShiftLeftBits(A[idx + slen], x);
                        Array.Copy(A[idx], 0, A[idx + slen], 0, A[idx].Length);   // copy A[idx] into A[idx+slen]
                        AddModFn(A[idx], d);
                        SubModFn(A[idx + slen], d, 1 << N);
                        idx++;
                    }
                }

                v++;
            }
        }

        /// <summary>
        /// Performs a modified Inverse Fermat Number Transform on an array whose elements are <c>int</c> arrays.
        /// </summary>
        /// 
        /// <param name="A">Array to process: Must be ceil(2^(n-1)) bits in length</param>
        /// <param name="M">M Value</param>
        /// <param name="N">N Value</param>
        /// 
        /// <remarks>
        /// The modification is that the last step (the one where the upper half is subtracted from the lower half) is omitted.
        /// <c>A</c> is assumed to be the upper half of the full array and the upper half is assumed to be all zeros.
        /// The number of subarrays in <c>A</c> must be 2^n if m is even and 2^(n+1) if m is odd.
        /// </remarks>
        public static void Idft(int[][] A, int M, int N)
        {
            bool even = M % 2 == 0;
            int len = A.Length;
            int v = N - 1;
            int[] c = new int[A[0].Length];

            for (int slen = 1; slen <= len / 2; slen *= 2)
            {   
                // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
                for (int j = 0; j < len; j += 2 * slen)
                {
                    int idx = j;
                    int idx2 = idx + slen;   // idx2 is always idx+slen
                    int x = GetIdftExponent(N, v, idx, even);

                    for (int k = slen - 1; k >= 0; k--)
                    {
                        Array.Copy(A[idx], 0, c, 0, c.Length);   // copy A[idx] into c
                        AddModFn(A[idx], A[idx2]);
                        A[idx] = CyclicShiftRight(A[idx], 1);

                        SubModFn(c, A[idx2], 1 << N);
                        A[idx2] = CyclicShiftRight(c, x);
                        idx++;
                        idx2++;
                    }
                }

                v--;
            }
        }

        /// <summary>
        /// Multiplies two BigIntegers using the Schönhage-Strassen algorithm.
        /// </summary>
        /// 
        /// <param name="A">Factor A</param>
        /// <param name="B">Factor B</param>
        /// 
        /// <returns>BigInteger equal to <c>A.Multiply(B)</c></returns>
        public static BigInteger Multiply(BigInteger A, BigInteger B)
        {
            // remove any minus signs, multiply, then fix sign
            int signum = A.Signum() * B.Signum();

            if (A.Signum() < 0)
                A = A.Negate();
            if (B.Signum() < 0)
                B = B.Negate();

            int[] aIntArr = ToIntArray(A);
            int[] bIntArr = ToIntArray(B);
            int[] cIntArr = Multiply(aIntArr, A.BitLength, bIntArr, B.BitLength);

            BigInteger c = ToBigInteger(cIntArr);

            if (signum < 0)
                c = c.Negate();

            return c;
        }

        /// <summary>
        /// Multiplies two positive numbers represented as int arrays, i.e. in base <c>2^32</c>.
        /// <para>Positive means an int is always interpreted as an unsigned number, regardless of the sign bit.<br/>
        /// The arrays must be ordered least significant to most significant,
        /// so the least significant digit must be at index 0.
        /// Schönhage-Strassen is used unless the numbers are in a range where
        /// <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba</a> is more efficient.</para>
        /// </summary>
        /// 
        /// <param name="A">Factor A</param>
        /// <param name="B">Factor B</param>
        /// 
        /// <returns>Array equal to <c>A * B</c></returns>
        public static int[] Multiply(int[] A, int[] B)
        {
            return Multiply(A, A.Length * 32, B, B.Length * 32);
        }

        /// <summary>
        /// Multiplies two positive numbers represented as <c>int</c> arrays using the Karatsuba algorithm
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Array equal to <c>A * B</c></returns>
        public static int[] MultKaratsuba(int[] A, int[] B)
        {
            int n = Math.Max(A.Length, B.Length);

            if (n <= KARATSUBA_THRESHOLD)
            {
                return MultSimple(A, B);
            }
            else
            {
                int n1 = (n + 1) / 2;
                int n1a = Math.Min(n1, A.Length);
                int n1b = Math.Min(n1, B.Length);

                int[] a1 = A.CopyOf(n1a);
                int[] a2 = n1a >= A.Length ? new int[0] : A.CopyOfRange(n1a, n);
                int[] b1 = B.CopyOf(n1);
                int[] b2 = n1b >= B.Length ? new int[0] : B.CopyOfRange(n1b, n);

                int[] a3 = AddExpand(a1, a2);
                int[] b3 = AddExpand(b1, b2);

                int[] c1 = MultKaratsuba(a1, b1);
                int[] c2 = MultKaratsuba(a2, b2);
                int[] c3 = MultKaratsuba(a3, b3);
                c3 = SubExpand(c3, c1);   // c3-c1>0 because a and b are positive
                c3 = SubExpand(c3, c2);   // c3-c2>0 because a and b are positive

                int[] c = c1.CopyOf(Math.Max(n1 + c3.Length, 2 * n1 + c2.Length));
                AddShifted(c, c3, n1);
                AddShifted(c, c2, 2 * n1);

                return c;
            }
        }

        /// <summary>
        /// Multiplies two positive numbers (meaning they are interpreted as unsigned) represented as
        /// <c>int</c> arrays using the simple O(n²) algorithm.
        /// </summary>
        /// 
        /// <param name="A">Array A: a number in base 2^32 starting with the lowest digit</param>
        /// <param name="B">Array B:  a number in base 2^32 starting with the lowest digit</param>
        /// 
        /// <returns>Array equal to <c>A * B</c></returns>
        public static int[] MultSimple(int[] A, int[] B)
        {
            int[] c = new int[A.Length + B.Length];
            long carry = 0;

            for (int i = 0; i < c.Length; i++)
            {
                long ci = c[i] & 0xFFFFFFFFL;
                for (int k = Math.Max(0, i - B.Length + 1); k < A.Length && k <= i; k++)
                {
                    long prod = (A[k] & 0xFFFFFFFFL) * (B[i - k] & 0xFFFFFFFFL);
                    ci += prod;
                    carry += (uint)(ci >> 32);
                    ci = (long)((ulong)(ci << 32) >> 32);
                }

                c[i] = (int)ci;
                if (i < c.Length - 1)
                    c[i + 1] = (int)carry;

                carry = (carry >> 32);
            }
            return c;
        }

        /// <summary>
        /// Multiplies two positive numbers (meaning they are interpreted as unsigned) modulo Fn where Fn=2^2^n+1, and returns the result in a new array.
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit; the length must be a power of 2</param>
        /// <param name="B">A number in base 2^32 starting with the lowest digit; the length must be a power of 2</param>
        /// 
        /// <returns>Result of calculation</returns>
        public static int[] MultModFn(int[] A, int[] B)
        {
            int[] a0 = A.CopyOf(A.Length / 2);
            int[] b0 = B.CopyOf(B.Length / 2);
            int[] c = Multiply(a0, b0);
            int n = A.Length / 2;

            // special case: if a=Fn-1, add b*2^2^n which is the same as subtracting b
            if (A[n] == 1)
                SubModFn(c, b0.CopyOf(c.Length), n * 32);
            if (B[n] == 1)
                SubModFn(c, a0.CopyOf(c.Length), n * 32);

            return c;
        }

        /// <summary>
        /// Reduces all subarrays modulo 2^2^n+1 where n=<c>a[i].Length*32/2</c> for all i;
        /// in other words, n is half the number of bits in the subarray.
        /// </summary>
        /// 
        /// <param name="A">Int array whose length is a power of 2</param>
        public static void ModFn(int[] A) 
        {
            int len = A.Length;
            bool carry = false;

            for (int i = 0; i < len / 2; i++) 
            {
                int bi = A[len / 2 + i];
                int diff = A[i] - bi;

                if (carry)
                    diff--;

                carry = (IntUtils.URShift(diff, 31) > (IntUtils.URShift(A[i], 31) - IntUtils.URShift(bi, 31)));   // carry if signBit(diff) > signBit(a)-signBit(b)
                A[i] = diff;
            }

            for (int i = len / 2; i < len; i++)
                A[i] = 0;

            // if result is negative, add Fn; since Fn â‰¡ 1 (mod 2^n), it suffices to add 1
            if (carry) 
            {
                int j = 0;
                do 
                {
                    int sum = A[j] + 1;
                    A[j] = sum;
                    carry = sum == 0;
                    j++;

                    if (j >= A.Length)
                        j = 0;

                } while (carry);
            }
        }

        /// <summary>
        /// Reduces all subarrays modulo 2^2^n+1 where n=<c>a[i].Length*32/2</c> for all i;
        /// in other words, n is half the number of bits in the subarray.
        /// </summary>
        /// 
        /// <param name="A">Int arrays whose length is a power of 2</param>
        [CLSCompliant(false)]
        public static void ModFn(int[][] A)
        {
            for (int i = 0; i < A.Length; i++)
                ModFn(A[i]);
        }

        /// <summary>
        /// Subtracts two positive numbers (meaning they are interpreted as unsigned) modulo 2^numBits.
        /// <para>Both input values are given as <c>int</c> arrays.
        /// The result is returned in the first argument.</para>
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="B">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="NumBits">The number of bits to shift</param>
        public static void SubModPow2(int[] A, int[] B, int NumBits)
        {
            int numElements = (NumBits + 31) / 32;
            bool carry = false;
            int i;

            for (i = 0; i < numElements; i++)
            {
                int diff = A[i] - B[i];
                if (carry)
                    diff--;

                carry = (IntUtils.URShift(diff, 31) > IntUtils.URShift(A[i], 31) - IntUtils.URShift(B[i], 31));   // carry if signBit(diff) > signBit(a)-signBit(b)
                A[i] = diff;
            }

            A[i - 1] &= IntUtils.URShift(-1, 32 - (NumBits % 32));

            for (; i < A.Length; i++)
                A[i] = 0;
        }

        /// <summary>
        /// Converts an <c>int</c> array to a <c>BigInteger</c>
        /// </summary>
        /// 
        /// <param name="A">The integer array</param>
        /// 
        /// <returns><c>BigInteger</c> representation of the array</returns>
        public static BigInteger ToBigInteger(int[] A)
        {
            byte[] b = new byte[A.Length * 4];

            for (int i = 0; i < A.Length; i++)
            {
                int iRev = A.Length - 1 - i;
                b[i * 4] = (byte)(A[iRev] >> 24);
                b[i * 4 + 1] = (byte)((A[iRev] >> 16) & 0xFF);
                b[i * 4 + 2] = (byte)((A[iRev] >> 8) & 0xFF);
                b[i * 4 + 3] = (byte)(A[iRev] & 0xFF);
            }

            return new BigInteger(1, b);
        }

        /// <summary>
        /// Converts a <c>BigInteger</c> to an <c>int</c> array.
        /// </summary>
        /// 
        /// <param name="A">BigInteger A</param>
        /// 
        /// <returns>An <c>int</c> array that is compatible with the <c>mult()</c> methods</returns>
        public static int[] ToIntArray(BigInteger A)
        {
            byte[] aArr = A.ToByteArray();
            int[] b = new int[(aArr.Length + 3) / 4];

            for (int i = 0; i < aArr.Length; i++)
                b[i / 4] += (aArr[aArr.Length - 1 - i] & 0xFF) << ((i % 4) * 8);

            return b;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Adds two positive numbers (meaning they are interpreted as unsigned) that are given as
        /// int arrays and returns the result in a new array. The result may be one longer
        /// than the input due to a carry.
        /// </summary>
        /// 
        /// <param name="A">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="B">A number in base 2^32 starting with the lowest digit</param>
        ///
        /// <returns>The sum</returns>
        private static int[] AddExpand(int[] A, int[] B)
        {
            int[] c = A.CopyOf(Math.Max(A.Length, B.Length));
            bool carry = false;
            int i = 0;

            while (i < Math.Min(B.Length, A.Length))
            {
                int sum = A[i] + B[i];
                if (carry)
                    sum++;

                carry = (IntUtils.URShift(sum, 31) < IntUtils.URShift(A[i], 31) + IntUtils.URShift(B[i], 31));   // carry if signBit(sum) < signBit(a)+signBit(b)
                c[i] = sum;
                i++;
            }
            while (carry)
            {
                if (i == c.Length)
                    c = c.CopyOf(c.Length + 1);

                c[i]++;
                carry = c[i] == 0;
                i++;
            }
            return c;
        }

        /// <summary>
        /// Adds two positive numbers (meaning they are interpreted as unsigned) modulo 2^numBits.
        /// Both input values are given as int arrays. The result is returned in the first argument.
        /// </summary>
        /// <param name="A">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="B">A number in base 2^32 starting with the lowest digit</param>
        /// <param name="NumBits">The modulo bit size</param>
        private static void AddModPow2(int[] A, int[] B, int NumBits)
        {
            int numElements = (NumBits + 31) / 32;
            bool carry = false;
            int i;

            for (i = 0; i < numElements; i++)
            {
                int sum = A[i] + B[i];
                if (carry)
                    sum++;

                // carry if signBit(sum) < signBit(a)+signBit(b)
                carry = (IntUtils.URShift(sum, 31) < IntUtils.URShift(A[i], 31) + IntUtils.URShift(B[i], 31));
                A[i] = sum;
            }

            A[i - 1] &= IntUtils.URShift(-1, 32 - (NumBits % 32));

            for (; i < A.Length; i++)
                A[i] = 0;
        }

        private static int GetDftExponent(int N, int V, int Idx, bool Even)
        {
            // take bits n-v..n-1 of idx, reverse them, shift left by n-v-1
            int x = IntUtils.URShift(IntUtils.ReverseInt(Idx) << (N - V), (31 - N));

            // if m is even, divide by two
            if (Even)
                x = IntUtils.URShift(x, 1);

            return x;
        }

        private static int GetIdftExponent(int N, int V, int Idx, bool Even)
        {
            int x = IntUtils.URShift(IntUtils.ReverseInt(Idx) << (N - V), (32 - N));

            if (Even)
                x += (1 << (N - V));
            else
                x += (1 << (N - 1 - V));

            return x + 1;
        }
        /// <remarks>
        /// <para>Schönhage-Strassen is used unless the numbers are in a range where
        /// <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba</a> is more efficient.</para>
        /// The Schönhage-Strassen algorithm works as follows:
        /// Given numbers a and b, split both numbers into pieces of length 2^(n-1) bits.
        /// Take the low n+2 bits of each piece of a, zero-pad them to 3n+5 bits, and concatenate them to a new number u.
        /// Do the same for b to obtain v.
        /// Calculate all pieces of z' by multiplying u and v (using Schönhage-Strassen or another algorithm). The product will contain all pieces of a*b mod n+2.
        /// Pad the pieces of a and b from step 1 to 2^(n+1) bits.
        /// Perform a <a href="http://en.wikipedia.org/wiki/Discrete_Fourier_transform_%28general%29#Number-theoretic_transform">
        /// Discrete Fourier Transform</a> (DFT) on the padded pieces.
        /// Calculate all pieces of z" by multiplying the i-th piece of a by the i-th piece of b.
        /// Perform an Inverse Discrete Fourier Transform (IDFT) on z". z" will contain all pieces of a*b mod Fn where Fn=2^2^n+1.
        /// Calculate all pieces of z such that each piece is congruent to z' modulo n+2 and congruent to z" modulo Fn. This is done using the
        /// <a href="http://en.wikipedia.org/wiki/Chinese_remainder_theorem">Chinese remainder theorem</a>.
        /// Calculate c by adding z_i * 2^(i*2^(n-1)) for all i, where z_i is the i-th piece of z.
        /// Return c reduced modulo 2^2^m+1.
        /// </remarks>
        private static int[] Multiply(int[] A, int ABitLen, int[] B, int BBitLen)
        {
            if (!ShouldUseSchonhageStrassen(Math.Max(ABitLen, BBitLen)))
                return MultKaratsuba(A, B);

            // set M to the number of binary digits in a or b, whichever is greater
            int M = Math.Max(ABitLen, BBitLen);
            // find the lowest m such that m>=log2(2M)
            int m = 32 - IntUtils.NumberOfLeadingZeros(2 * M - 1 - 1);
            int n = m / 2 + 1;
            // split a and b into pieces 1<<(n-1) bits long; assume n>=6 so pieces start and end at int boundaries
            bool even = m % 2 == 0;
            int numPieces = even ? 1 << n : 1 << (n + 1);
            int pieceSize = 1 << (n - 1 - 5);   // in ints
            // build u and v from a and b, allocating 3n+5 bits in u and v per n+2 bits from a and b, resp.
            int numPiecesA = (A.Length + pieceSize) / pieceSize;
            int[] u = new int[(numPiecesA * (3 * n + 5) + 31) / 32];
            int uBitLength = 0;

            for (int i = 0; i < numPiecesA && i * pieceSize < A.Length; i++)
            {
                AppendBits(u, uBitLength, A, i * pieceSize, n + 2);
                uBitLength += 3 * n + 5;
            }

            int numPiecesB = (B.Length + pieceSize) / pieceSize;
            int[] v = new int[(numPiecesB * (3 * n + 5) + 31) / 32];
            int vBitLength = 0;

            for (int i = 0; i < numPiecesB && i * pieceSize < B.Length; i++)
            {
                AppendBits(v, vBitLength, B, i * pieceSize, n + 2);
                vBitLength += 3 * n + 5;
            }

            int[] gamma = Multiply(u, uBitLength, v, vBitLength);
            int[][] gammai = SplitBits(gamma, 3 * n + 5);
            int halfNumPcs = numPieces / 2;
            int[][] zi = new int[gammai.Length][];

            for (int i = 0; i < gammai.Length; i++)
                zi[i] = gammai[i];
            for (int i = 0; i < gammai.Length - halfNumPcs; i++)
                SubModPow2(zi[i], gammai[i + halfNumPcs], n + 2);
            for (int i = 0; i < gammai.Length - 2 * halfNumPcs; i++)
                AddModPow2(zi[i], gammai[i + 2 * halfNumPcs], n + 2);
            for (int i = 0; i < gammai.Length - 3 * halfNumPcs; i++)
                SubModPow2(zi[i], gammai[i + 3 * halfNumPcs], n + 2);

            // zr mod Fn
            int[][] ai = SplitInts(A, halfNumPcs, pieceSize, 1 << (n + 1 - 5));
            int[][] bi = SplitInts(B, halfNumPcs, pieceSize, 1 << (n + 1 - 5));
            Dft(ai, m, n);
            Dft(bi, m, n);
            ModFn(ai);
            ModFn(bi);
            int[][] c = new int[halfNumPcs][];

            for (int i = 0; i < c.Length; i++)
                c[i] = MultModFn(ai[i], bi[i]);

            Idft(c, m, n);
            ModFn(c);

            int[] z = new int[1 << (m + 1 - 5)];
            // calculate zr mod Fm from zr mod Fn and zr mod 2^(n+2), then add to z
            for (int i = 0; i < halfNumPcs; i++)
            {
                int[] eta = i >= zi.Length ? new int[(n + 2 + 31) / 32] : zi[i];
                // zi = delta = (zi-c[i]) % 2^(n+2)
                SubModPow2(eta, c[i], n + 2);
                // z += zr<<shift = [ci + delta*(2^2^n+1)] << [i*2^(n-1)]
                int shift = i * (1 << (n - 1 - 5));   // assume n>=6
                AddShifted(z, c[i], shift);
                AddShifted(z, eta, shift);
                AddShifted(z, eta, shift + (1 << (n - 5)));
            }

            // assume m>=5
            ModFn(z); 

            return z;
        }

        /// <remarks>
        /// Estimates whether SS or Karatsuba will be more efficient when multiplying two numbers of a given length in bits.
        /// </remarks>
        private static bool ShouldUseSchonhageStrassen(int BitLength)
        {
            // The following values were determined experimentally on a 32-bit JVM.
            if (BitLength < 93600)
                return false;
            if (BitLength < 131072)
                return true;
            if (BitLength < 159300)
                return false;

            return true;
        }

        /// <remarks>
        /// Divides an int array into pieces BitLength bits long.
        /// </remarks>
        private static int[][] SplitBits(int[] A, int BitLength)
        {
            int aIntIdx = 0;
            int aBitIdx = 0;
            int numPieces = (A.Length * 32 + BitLength - 1) / BitLength;
            int pieceLength = (BitLength + 31) / 32;   // in ints
            int[][] b = ArrayUtils.CreateJagged<int[][]>(numPieces, pieceLength);

            for (int i = 0; i < b.Length; i++)
            {
                int bitsRemaining = Math.Min(BitLength, A.Length * 32 - i * BitLength);
                int bIntIdx = 0;
                int bBitIdx = 0;

                while (bitsRemaining > 0)
                {
                    int bitsToCopy = Math.Min(32 - aBitIdx, 32 - bBitIdx);
                    bitsToCopy = Math.Min(bitsRemaining, bitsToCopy);
                    int mask = IntUtils.URShift(A[aIntIdx], aBitIdx);
                    mask &= IntUtils.URShift(-1, (32 - bitsToCopy));
                    mask <<= bBitIdx;
                    b[i][bIntIdx] |= mask;
                    bitsRemaining -= bitsToCopy;
                    aBitIdx += bitsToCopy;

                    if (aBitIdx >= 32)
                    {
                        aBitIdx -= 32;
                        aIntIdx++;
                    }

                    bBitIdx += bitsToCopy;
                    if (bBitIdx >= 32)
                    {
                        bBitIdx -= 32;
                        bIntIdx++;
                    }
                }
            }
            return b;
        }

        /// <remarks>
        /// Splits an int array into pieces of pieceSize ints each, and
        /// pads each piece to TargetPieceSize ints.
        /// </remarks>
        private static int[][] SplitInts(int[] A, int NumPieces, int PieceSize, int TargetPieceSize)
        {
            int[][] ai = ArrayUtils.CreateJagged<int[][]>(NumPieces, TargetPieceSize);

            for (int i = 0; i < A.Length / PieceSize; i++)
                Array.Copy(A, i * PieceSize, ai[i], 0, PieceSize);

            Array.Copy(A, A.Length / PieceSize * PieceSize, ai[A.Length / PieceSize], 0, A.Length % PieceSize);

            return ai;
        }

        /// <remarks>
        /// Subtracts two positive numbers (meaning they are interpreted as unsigned) that are given as
        /// int arrays and returns the result in a new array.
        /// </remarks>
        private static int[] SubExpand(int[] A, int[] B)
        {
            int[] c = A.CopyOf(Math.Max(A.Length, B.Length));
            bool carry = false;
            int i = 0;

            while (i < Math.Min(B.Length, A.Length))
            {
                int diff = A[i] - B[i];
                if (carry)
                    diff--;

                // carry if signBit(diff) > signBit(a)-signBit(b)
                carry = (IntUtils.URShift(diff, 31) > IntUtils.URShift(A[i], 31) - IntUtils.URShift(B[i], 31));
                c[i] = diff;
                i++;
            }
            while (carry)
            {
                c[i]--;
                carry = c[i] == -1;
                i++;
            }

            return c;
        }

        /// <remarks>
        /// Subtracts two positive numbers (meaning they are interpreted as unsigned) modulo 2^2^n+1,
        /// where n is a.Length*32/2; in other words, n is half the number of bits in A.
        /// Both input values are given as int arrays; they must be the same length.
        /// The result is returned in the first argument.
        /// </remarks>
        private static void SubModFn(int[] A, int[] B, int Pow2n)
        {
            AddModFn(A, CyclicShiftLeftElements(B, Pow2n / 32));
        }
        #endregion
    }
}