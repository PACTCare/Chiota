#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// BigMath: Class of number-theory related functions for use with integers represented as <c>int</c>'s or <c>BigInteger</c> objects.
    /// </summary>
    public sealed class BigMath
    {
        #region Fields
        private static BigInteger ZERO = BigInteger.ValueOf(0);
        private static BigInteger ONE = BigInteger.ValueOf(1);
        private static BigInteger TWO = BigInteger.ValueOf(2);
        private static BigInteger FOUR = BigInteger.ValueOf(4);
        private static int[] SMALL_PRIMES = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41 };
        private static long SMALL_PRIME_PRODUCT = 3L * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31 * 37 * 41;
        private static SecureRandom m_secRnd = null;
        // the jacobi function uses this lookup table
        private static readonly int[] m_jacobiTable = { 0, 1, 0, -1, 0, -1, 0, 1 };
        #endregion

        #region Constructor
        private BigMath()
        {
        }
        #endregion

        #region Methods
        /// <summary>
        /// Computes the binomial coefficient (n|t)
        /// </summary>
        /// 
        /// <param name="X">The upper integer</param>
        /// <param name="T">The lower integer</param>
        /// 
        /// <returns>Returns the binomialcoefficient (n|t) as BigInteger</returns>
        public static BigInteger Binomial(int X, int T)
        {
            BigInteger result = ONE;

            if (X == 0)
            {
                if (T == 0)
                    return result;

                return ZERO;
            }

            // the property (n|t) = (n|n-t) be used to reduce numbers of operations
            if (T > (IntUtils.URShift(X, 1)))
                T = X - T;

            for (int i = 1; i <= T; i++)
                result = (result.Multiply(BigInteger.ValueOf(X - (i - 1)))).Divide(BigInteger.ValueOf(i));

            return result;
        }

        /// <summary>
        /// Get the number of ones in the binary representation of an integer <c>A</c>
        /// </summary>
        /// 
        /// <param name="X">n integer</param>
        /// 
        /// <returns>Returns the number of ones in the binary representation of an integer <c>A</c></returns>
        public static int BitCount(int X)
        {
            int h = 0;
            while (X != 0)
            {
                h += X & 1;
                X = IntUtils.URShift(X, 1);
            }

            return h;
        }

        /// <summary>
        /// Compute the smallest integer that is greater than or equal to the logarithm to the base 2 of the given BigInteger
        /// </summary>
        /// 
        /// <param name="X">The BigInteger</param>
        /// 
        /// <returns>Returns <c>ceil[log(a)]</c></returns>
        public static int CeilLog(BigInteger X)
        {
            int result = 0;
            BigInteger p = ONE;
            while (p.CompareTo(X) < 0)
            {
                result++;
                p = p.ShiftLeft(1);
            }

            return result;
        }

        /// <summary>
        /// Compute the smallest integer that is greater than or equal to the logarithm to the base 2 of the given integer
        /// </summary>
        /// 
        /// <param name="X">The integer</param>
        /// 
        /// <returns>Returns <c>ceil[log(a)]</c></returns>
        public static int CeilLog(int X)
        {
            int log = 0;
            int i = 1;
            while (i < X)
            {
                i <<= 1;
                log++;
            }

            return log;
        }

        /// <summary>
        /// Compute <c>ceil(log_256 n)</c>, the number of bytes needed to encode the integer <c>N</c>
        /// </summary>
        /// 
        /// <param name="X">The integer</param>
        /// 
        /// <returns>Returns the number of bytes needed to encode <c>N</c></returns>
        public static int CeilLog256(int X)
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
        /// Compute <c>ceil(log_256 n)</c>, the number of bytes needed to encode the long integer <c>N</c>
        /// </summary>
        /// 
        /// <param name="X">The long integer</param>
        /// 
        /// <returns>Returns the number of bytes needed to encode <c>N</c></returns>
        public static int CeilLog256(long X)
        {
            if (X == 0)
                return 1;
            long m;
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
        /// Divide two BigIntegers and return the rounded result
        /// </summary>
        /// 
        /// <param name="A">The first BigInteger</param>
        /// <param name="B">The second BigInteger</param>
        /// 
        /// <returns>The rounded result</returns>
        public static BigInteger DivideAndRound(BigInteger A, BigInteger B)
        {
            if (A.Signum() < 0)
                return DivideAndRound(A.Negate(), B).Negate();
            if (B.Signum() < 0)
                return DivideAndRound(A, B.Negate()).Negate();
            
            return A.ShiftLeft(1).Add(B).Divide(B.ShiftLeft(1));
        }

        /// <summary>
        /// Divide two BigInteger arrays and return the rounded result
        /// </summary>
        /// 
        /// <param name="A">The first BigInteger array</param>
        /// <param name="B">The second BigInteger array</param>
        /// 
        /// <returns>The rounded result</returns>
        public static BigInteger[] DivideAndRound(BigInteger[] A, BigInteger B)
        {
            BigInteger[] Bout = new BigInteger[A.Length];
            for (int i = 0; i < A.Length; i++)
                Bout[i] = DivideAndRound(A[i], B);
            
            return Bout;
        }

        /// <summary>
        /// Extended euclidian algorithm (computes Gcd and representation)
        /// </summary>
        /// 
        /// <param name="A">The first BigInteger</param>
        /// <param name="B">The second BigInteger</param>
        /// 
        /// <returns>Returns <c>(d,u,v)</c>, where <c>d = Gcd(A,B) = ua + vb</c></returns>
        public static BigInteger[] ExtGcd(BigInteger A, BigInteger B)
        {
            BigInteger u = ONE;
            BigInteger v = ZERO;
            BigInteger d = A;

            if (B.Signum() != 0)
            {
                BigInteger v1 = ZERO;
                BigInteger v3 = B;
                while (v3.Signum() != 0)
                {
                    BigInteger[] tmp = d.DivideAndRemainder(v3);
                    BigInteger q = tmp[0];
                    BigInteger t3 = tmp[1];
                    BigInteger t1 = u.Subtract(q.Multiply(v1));
                    u = v1;
                    d = v3;
                    v1 = t1;
                    v3 = t3;
                }
                v = d.Subtract(A.Multiply(u)).Divide(B);
            }

            return new BigInteger[] { d, u, v };
        }

        /// <summary>
        /// Extended euclidian algorithm (computes gcd and representation)
        /// </summary>
        /// 
        /// <param name="A">The first integer</param>
        /// <param name="B">The second integer</param>
        /// 
        /// <returns>Returns <c>(g,u,v)</c>, where <c>g = Gcd(Abs(A),Abs(B)) = ua + vb</c></returns>
        public static int[] ExtGcd(int A, int B)
        {
            BigInteger ba = BigInteger.ValueOf(A);
            BigInteger bb = BigInteger.ValueOf(B);
            BigInteger[] bresult = ExtGcd(ba, bb);
            int[] result = new int[3];

            result[0] = bresult[0].ToInt32();
            result[1] = bresult[1].ToInt32();
            result[2] = bresult[2].ToInt32();

            return result;
        }

        /// <summary>
        /// Calculation of a logarithmus of a float param
        /// </summary>
        /// 
        /// <param name="X">The float value</param>
        /// 
        /// <returns>Returns <c>Log(A)</c></returns>
        public static float FloatLog(float X)
        {
            double arg = (X - 1) / (X + 1);
            double arg2 = arg;
            int counter = 1;
            float result = (float)arg;

            while (arg2 > 0.001)
            {
                counter += 2;
                arg2 *= arg * arg;
                result += (float)((1.0 / counter) * arg2);
            }

            return 2 * result;
        }

        /// <summary>
        /// Returns the int power of a base float, only use for small ints
        /// </summary>
        /// 
        /// <param name="X">The float value</param>
        /// <param name="E">The exponent</param>
        /// 
        /// <returns>Returns <c>A^E</c></returns>
        public static float FloatPow(float X, int E)
        {
            float g = 1;
            for (; E > 0; E--)
                g *= X;
            
            return g;
        }

        /// <summary>
        /// Compute the integer part of the logarithm to the base 2 of the given integer
        /// </summary>
        /// 
        /// <param name="X">The integer</param>
        /// 
        /// <returns>Returns floor[log(a)]</returns>
        public static int FloorLog(BigInteger X)
        {
            int result = -1;
            BigInteger p = ONE;

            while (p.CompareTo(X) <= 0)
            {
                result++;
                p = p.ShiftLeft(1);
            }

            return result;
        }

        /// <summary>
        /// Compute the integer part of the logarithm to the base 2 of the given integer
        /// </summary>
        /// 
        /// <param name="X">The integer</param>
        /// 
        /// <returns>Returns floor[log(a)]</returns>
        public static int FloorLog(int X)
        {
            int h = 0;
            if (X <= 0)
                return -1;
            
            int p = IntUtils.URShift(X, 1);
            while (p > 0)
            {
                h++;
                p = IntUtils.URShift(p, 1);
            }

            return h;
        }

        /// <summary>
        /// Computes the greatest common divisor of the two specified integers
        /// </summary>
        /// 
        /// <param name="A">The first integer</param>
        /// <param name="B">The  second integer</param>
        /// 
        /// <returns>Returns <c>Gcd(a, b)</c></returns>
        public static int Gcd(int A, int B)
        {
            return BigInteger.ValueOf(A).Gcd(BigInteger.ValueOf(B)).ToInt32();
        }

        /// <summary>
        /// Takes an approximation of the root from an integer base, using newton's algorithm
        /// </summary>
        /// 
        /// <param name="X">The base to take the root from</param>
        /// <param name="Root">The root, for example 2 for a square root</param>
        /// 
        /// <returns>Returns the integers base root</returns>
        public static float IntRoot(int X, int Root)
        {
            float gNew = X / Root;
            float gOld = 0;
            int counter = 0;

            while (Math.Abs(gOld - gNew) > 0.0001)
            {
                float gPow = FloatPow(gNew, Root);
                while (float.IsInfinity(gPow))
                {
                    gNew = (gNew + gOld) / 2;
                    gPow = FloatPow(gNew, Root);
                }
                counter += 1;
                gOld = gNew;
                gNew = gOld - (gPow - X) / (Root * FloatPow(gOld, Root - 1));
            }

            return gNew;
        }

        /// <summary>
        /// Convert a BigInteger to bytes
        /// </summary>
        /// 
        /// <param name="X">The BigInteger</param>
        /// 
        /// <returns>Returns the BigInteger as a byte array</returns>
        public static byte[] IntToOctets(BigInteger X)
        {
            byte[] valBytes = X.Abs().ToByteArray();

            // check whether the array includes a sign bit
            if ((X.BitLength & 7) != 0)
                return valBytes;

            // get rid of the sign bit (first byte)
            byte[] tmp = new byte[X.BitLength >> 3];
            Array.Copy(valBytes, 1, tmp, 0, tmp.Length);

            return tmp;
        }

        /// <summary>
        /// Tests if the integers are incrementing
        /// </summary>
        /// 
        /// <param name="A">The array to test</param>
        /// 
        /// <returns>Returns <c>true</c> if array values are incrementing</returns>
        public static bool IsIncreasing(int[] A)
        {
            for (int i = 1; i < A.Length; i++)
            {
                if (A[i - 1] >= A[i])
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Tests whether an integer <c>a</c> is power of another integer <c>P</c>
        /// </summary>
        /// 
        /// <param name="X">The first integer</param>
        /// <param name="P">The second integer</param>
        /// 
        /// <returns>Returns n if A = P^n or -1 otherwise</returns>
        public static int IsPower(int X, int P)
        {
            if (X <= 0)
                return -1;
            
            int n = 0;
            int d = X;
            while (d > 1)
            {
                if (d % P != 0)
                    return -1;
                
                d /= P;
                n++;
            }
            return n;
        }

        /// <summary>
        /// Miller-Rabin-Test, determines wether the given integer is probably prime or composite.
        /// <para>This method returns <c>true</c> if the given integer is prime with probability <c>1 - 2^-20</c>.</para>
        /// </summary>
        /// 
        /// <param name="X">The integer to test for primality</param>
        /// 
        /// <returns>Returns <c>true</c> if the given integer is prime with probability 2*-100, otherwise <c>false</c></returns>
        public static bool IsPrime(int X)
        {
            if (X < 2)
                return false;
            if (X == 2)
                return true;
            if ((X & 1) == 0)
                return false;
            
            if (X < 42)
            {
                for (int i = 0; i < SMALL_PRIMES.Length; i++)
                {
                    if (X == SMALL_PRIMES[i])
                        return true;
                }
            }

            if ((X % 3 == 0) || (X % 5 == 0) || (X % 7 == 0) || (X % 11 == 0)
                || (X % 13 == 0) || (X % 17 == 0) || (X % 19 == 0)
                || (X % 23 == 0) || (X % 29 == 0) || (X % 31 == 0)
                || (X % 37 == 0) || (X % 41 == 0))
            {
                return false;
            }

            return BigInteger.ValueOf(X).IsProbablePrime(20);
        }

        /// <summary>
        /// Short trial-division test to find out whether a number is not prime.
        /// <para>This test is usually used before a Miller-Rabin primality test.</para>
        /// </summary>
        /// 
        /// <param name="Candidate">he number to test</param>
        /// 
        /// <returns>Returns <c>true</c> if the number has no factor of the tested primes, <c>false</c> if the number is definitely composite</returns>
        public static bool IsSmallPrime(BigInteger Candidate)
        {
            int[] smallPrime = 
            {
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
                107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
                173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
                239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
                311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
                383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
                457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
                541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
                613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
                683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
                769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853,
                857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
                941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
                1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
                1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
                1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
                1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297,
                1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381,
                1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453,
                1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499
            };

            for (int i = 0; i < smallPrime.Length; i++)
            {
                if (Candidate.Mod(BigInteger.ValueOf(smallPrime[i])).Equals(ZERO))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Computes the value of the Jacobi symbol (A|B). 
        /// </summary>
        /// 
        /// <param name="A">The integer value</param>
        /// <param name="B">The integer value</param>
        /// 
        /// <returns>Returns value of the jacobi symbol (A|B)</returns>
        public static int Jacobi(BigInteger A, BigInteger B)
        {
            BigInteger a, b, v;
            long k = 1;

            // test trivial cases
            if (B.Equals(ZERO))
            {
                a = A.Abs();
                return a.Equals(ONE) ? 1 : 0;
            }

            if (!A.TestBit(0) && !B.TestBit(0))
                return 0;

            a = A;
            b = B;

            if (b.Signum() == -1)
            { // b < 0
                b = b.Negate();
                if (a.Signum() == -1)
                    k = -1;
            }

            v = ZERO;
            while (!b.TestBit(0))
            {
                v = v.Add(ONE); 
                b = b.Divide(TWO);
            }

            if (v.TestBit(0))
                k = k * m_jacobiTable[a.ToInt32() & 7];

            if (a.Signum() < 0)
            { 
                if (b.TestBit(1))
                    k = -k; 
                a = a.Negate(); 
            }

            // main loop
            while (a.Signum() != 0)
            {
                v = ZERO;
                while (!a.TestBit(0))
                { // a is even
                    v = v.Add(ONE);
                    a = a.Divide(TWO);
                }
                if (v.TestBit(0))
                    k = k * m_jacobiTable[b.ToInt32() & 7];

                if (a.CompareTo(b) < 0)
                {
                    // swap and correct intermediate result
                    BigInteger x = a;
                    a = b;
                    b = x;
                    if (a.TestBit(1) && b.TestBit(1))
                        k = -k;
                }
                a = a.Subtract(b);
            }

            return b.Equals(ONE) ? (int)k : 0;
        }

        /// <summary>
        /// Computation of the least common multiple of a set of BigIntegers
        /// </summary>
        /// 
        /// <param name="Numbers">The set of numbers</param>
        /// 
        /// <returns>Returns the lcm(Numbers)</returns>
        public static BigInteger Lcm(BigInteger[] Numbers)
        {
            int n = Numbers.Length;
            BigInteger result = Numbers[0];
            for (int i = 1; i < n; i++)
            {
                BigInteger gcd = result.Gcd(Numbers[i]);
                result = result.Multiply(Numbers[i]).Divide(gcd);
            }

            return result;
        }

        /// <summary>
        /// Find and return the least non-trivial divisor of an integer <c>A</c>
        /// </summary>
        /// 
        /// <param name="X">The integer</param>
        /// 
        /// <returns>Returns divisor p &gt;1 or 1 if A = -1,0,1</returns>
        public static int LeastDiv(int X)
        {
            if (X < 0)
                X = -X;
            if (X == 0)
                return 1;
            if ((X & 1) == 0)
                return 2;
            
            int p = 3;
            while (p <= (X / p))
            {
                if ((X % p) == 0)
                    return p;
                p += 2;
            }

            return X;
        }

        /// <summary>
        /// Calculates the logarithm to the base 2
        /// </summary>
        /// 
        /// <param name="X"> double value</param>
        /// 
        /// <returns>Returns log_2(x)</returns>
        public static double Log(double X)
        {
            if (X > 0 && X < 1)
            {
                double d = 1 / X;
                double result = -Log(d);
                return result;
            }

            int tmp = 0;
            double tmp2 = 1;
            double d2 = X;

            while (d2 > 2)
            {
                d2 = d2 / 2;
                tmp += 1;
                tmp2 *= 2;
            }
            double rem = X / tmp2;
            rem = LogBKM(rem);

            return tmp + rem;
        }

        /// <summary>
        /// Calculate the logarithm to the base 2
        /// </summary>
        /// 
        /// <param name="X">Any long value &gt;=1</param>
        /// 
        /// <returns>Returns <c>log_2(x)</c></returns>
        public static double Log(long X)
        {
            int tmp = FloorLog(BigInteger.ValueOf(X));
            long tmp2 = 1 << tmp;
            double rem = (double)X / (double)tmp2;
            rem = LogBKM(rem);

            return tmp + rem;
        }

        /// <summary>
        /// Compute the largest <c>h</c> with <c>2^h | A</c> if <c>A!=0</c>
        /// </summary>
        /// 
        /// <param name="X">An integer</param>
        /// 
        /// <returns>Returns the largest <c>h</c> with <c>2^h | A</c> if <c>A!=0</c>, <c>0</c> otherwise</returns>
        public static int MaxPower(int X)
        {
            int h = 0;
            if (X != 0)
            {
                int p = 1;
                while ((X & p) == 0)
                {
                    h++;
                    p <<= 1;
                }
            }

            return h;
        }

        /// <summary>
        /// Returns a long integer whose value is <c>(A mod M</c>). 
        /// <para>This method differs from <c>%</c> in that it always returns a <c>non-negative</c> integer.</para>
        /// </summary>
        /// 
        /// <param name="X">The value on which the modulo operation has to be performed</param>
        /// <param name="M">The modulus.</param>
        /// 
        /// <returns>Returns <c>A mod M</c></returns>
        public static long Mod(long X, long M)
        {
            long result = X % M;
            if (result < 0)
                result += M;
            
            return result;
        }

        /// <summary>
        /// Computes the modular inverse of an integer A
        /// </summary>
        /// 
        /// <param name="X">The integer to invert</param>
        /// <param name="Mod">The modulus</param>
        /// 
        /// <returns>Returns <c>A<sup>-1</sup> Mod n</c></returns>
        public static int ModInverse(int X, int Mod)
        {
            return BigInteger.ValueOf(X).ModInverse(BigInteger.ValueOf(Mod)).ToInt32();
        }

        /// <summary>
        /// Computes the modular inverse of an integer A
        /// </summary>
        /// 
        /// <param name="X">The integer to invert</param>
        /// <param name="Mod">The modulus</param>
        /// 
        /// <returns>Returns <c>A<sup>-1</sup> Mod n</c></returns>
        public static long ModInverse(long X, long Mod)
        {
            return BigInteger.ValueOf(X).ModInverse(BigInteger.ValueOf(Mod)).ToInt64();
        }

        /// <summary>
        /// Compute <c>A^E mod N</c>
        /// </summary>
        /// 
        /// <param name="X">The base</param>
        /// <param name="E">The exponent</param>
        /// <param name="N">The modulus</param>
        /// 
        /// <returns>Returns <c>A<sup>E</sup> mod N</c></returns>
        public static int ModPow(int X, int E, int N)
        {
            if (N <= 0 || (N * N) > int.MaxValue || E < 0)
                return 0;
            
            int result = 1;
            X = (X % N + N) % N;
            while (E > 0)
            {
                if ((E & 1) == 1)
                    result = (result * X) % N;
                
                X = (X * X) % N;
                E = IntUtils.URShift(E, 1);
            }

            return result;
        }

        /// <summary>
        /// Computes the next prime greater than N
        /// </summary>
        /// 
        /// <param name="X">An integer number</param>
        /// 
        /// <returns>Returns the next prime greater than <c>N</c></returns>
        public static BigInteger NextPrime(long X)
        {
            long i;
            bool found = false;
            long result = 0;

            if (X <= 1)
                return BigInteger.ValueOf(2);
            if (X == 2)
                return BigInteger.ValueOf(3);

            for (i = X + 1 + (X & 1); (i <= X << 1) && !found; i += 2)
            {
                for (long j = 3; (j <= i >> 1) && !found; j += 2)
                {
                    if (i % j == 0)
                        found = true;
                }
                if (found)
                {
                    found = false;
                }
                else
                {
                    result = i;
                    found = true;
                }
            }

            return BigInteger.ValueOf(result);
        }

        /// <summary>
        /// Compute the next probable prime greater than <c>N</c> with the specified certainty
        /// </summary>
        /// 
        /// <param name="X">An integer number</param>
        /// <param name="Certainty">The certainty that the generated number is prime</param>
        /// 
        /// <returns>Returns the next prime greater than <c>N</c></returns>
        public static BigInteger NextProbablePrime(BigInteger X, int Certainty)
        {
            if (X.Signum() < 0 || X.Signum() == 0 || X.Equals(ONE))
                return TWO;

            BigInteger result = X.Add(ONE);

            // Ensure an odd number
            if (!result.TestBit(0))
                result = result.Add(ONE);

            while (true)
            {
                // Do cheap "pre-test" if applicable
                if (result.BitLength > 6)
                {
                    long r = result.Remainder(BigInteger.ValueOf(SMALL_PRIME_PRODUCT)).ToInt64();
                    if ((r % 3 == 0) || (r % 5 == 0) || (r % 7 == 0) || 
                        (r % 11 == 0) || (r % 13 == 0) || (r % 17 == 0) || 
                        (r % 19 == 0) || (r % 23 == 0) || (r % 29 == 0) || 
                        (r % 31 == 0) || (r % 37 == 0) || (r % 41 == 0))
                    {
                        result = result.Add(TWO);
                        continue; // Candidate is composite; try another
                    }
                }

                // All candidates of bitLength 2 and 3 are prime by this point
                if (result.BitLength < 4)
                    return result;

                // The expensive test
                if (result.IsProbablePrime(Certainty))
                    return result;

                result = result.Add(TWO);
            }
        }

        /// <summary>
        /// Compute the next probable prime greater than <c>N</c> with the default certainty (20)
        /// </summary>
        /// 
        /// <param name="X">An integer number</param>
        /// 
        /// <returns>The next prime greater than <c>N</c></returns>
        public static BigInteger NextProbablePrime(BigInteger X)
        {
            return NextProbablePrime(X, 20);
        }

        /// <summary>
        /// Returns the largest prime smaller than the given integer
        /// </summary>
        /// 
        /// <param name="X"> upper bound</param>
        /// 
        /// <returns>Returns the largest prime smaller than <c>N</c>, or <c>1</c> if <c>N &lt;= 2</c></returns>
        public static int NextSmallerPrime(int X)
        {
            if (X <= 2)
                return 1;
            if (X == 3)
                return 2;
            if ((X & 1) == 0)
                X--;
            else
                X -= 2;

            while (X > 3 & !IsPrime(X))
                X -= 2;
            
            return X;
        }

        /// <summary>
        /// Create a BigInteger from a byte array
        /// </summary>
        /// 
        /// <param name="Data">The source byte array</param>
        /// 
        /// <returns>Returns the BigInteger</returns>
        public static BigInteger OctetsToInteger(byte[] Data)
        {
            return OctetsToInteger(Data, 0, Data.Length);
        }

        /// <summary>
        /// Create a BigInteger from a byte array
        /// </summary>
        /// 
        /// <param name="Data">The source byte array</param>
        /// <param name="Offset">The starting offset within the array</param>
        /// <param name="Length">The number of bytes used to create the BigInteger</param>
        /// 
        /// <returns>Returns the BigInteger</returns>
        public static BigInteger OctetsToInteger(byte[] Data, int Offset, int Length)
        {
            byte[] val = new byte[Length + 1];
            val[0] = 0;
            Array.Copy(Data, Offset, val, 1, Length);

            return new BigInteger(val);
        }

        /// <summary>
        /// Determines the order of G modulo P, P prime and 1 &lt; g &lt; p; This algorithm is only efficient for small P
        /// </summary>
        /// 
        /// <param name="G">An integer with 1 &lt; G &lt; P</param>
        /// <param name="P">The prime</param>
        /// 
        /// <returns>Returns the order k of g (that is k is the smallest integer with G^k = 1 mod P</returns>
        public static int Order(int G, int P)
        {
            int b, j;

            b = G % P; // Reduce g mod p first.
            j = 1;

            // Check whether g == 0 mod p (avoiding endless loop).
            if (b == 0)
                throw new ArgumentException(G + " is not an element of Z/(" + P + "Z)^*; it is not meaningful to compute its order.");

            // Compute the order of g mod p:
            while (b != 1)
            {
                b *= G;
                b %= P;
                if (b < 0)
                    b += P;
                
                j++;
            }

            return j;
        }

        /// <summary>
        /// Compute <c>A^E</c>
        /// </summary>
        /// 
        /// <param name="X">The base</param>
        /// <param name="E">The exponent</param>
        /// 
        /// <returns>Returns <c>A^E</c></returns>
        public static int Pow(int X, int E)
        {
            int result = 1;
            while (E > 0)
            {
                if ((E & 1) == 1)
                    result *= X;
                X *= X;
                E = IntUtils.URShift(E, 1);
            }

            return result;
        }

        /// <summary>
        /// Compute <c>A^E</c>
        /// </summary>
        /// 
        /// <param name="X">The base</param>
        /// <param name="E">The exponent</param>
        /// 
        /// <returns>Returns <c>A^E</c></returns>
        public static long Pow(long X, int E)
        {
            long result = 1;
            while (E > 0)
            {
                if ((E & 1) == 1)
                    result *= X;
                
                X *= X;
                E = IntUtils.URShift(E, 1);
            }
            return result;
        }

        /// <summary>
        /// Create a random BigInteger
        /// </summary>
        /// 
        /// <param name="UpperBound">The upper bound</param>
        /// 
        /// <returns>A random BigInteger</returns>
        public static BigInteger Randomize(BigInteger UpperBound)
        {
            if (m_secRnd == null)
                m_secRnd = new SecureRandom();
            
            return Randomize(UpperBound, m_secRnd);
        }

        /// <summary>
        /// Reduces an integer into a given interval
        /// </summary>
        /// 
        /// <param name="X">The integer</param>
        /// <param name="Begin">Left bound of the interval</param>
        /// <param name="End">Right bound of the interval</param>
        /// 
        /// <returns>Returns <c>N</c> reduced into <c>[Begin,End]</c></returns>
        public static BigInteger ReduceInto(BigInteger X, BigInteger Begin, BigInteger End)
        {
            return X.Subtract(Begin).Mod(End.Subtract(Begin)).Add(Begin);
        }

        /// <summary>
        /// Computes the square root of a BigInteger modulo a prime employing the Shanks-Tonelli algorithm
        /// </summary>
        /// 
        /// <param name="X">The value out of which we extract the square root</param>
        /// <param name="P">The prime modulus that determines the underlying field</param>
        /// 
        /// <returns>Returns a number <c>B</c> such that B^2 = A (mod P) if <c>A</c> is a quadratic residue modulo <c>P</c></returns>
        public static BigInteger Ressol(BigInteger X, BigInteger P)
        {
            BigInteger v = null;

            if (X.CompareTo(ZERO) < 0)
                X = X.Add(P);
            if (X.Equals(ZERO))
                return ZERO;
            if (P.Equals(TWO))
                return X;

            // p = 3 mod 4
            if (P.TestBit(0) && P.TestBit(1))
            {
                if (Jacobi(X, P) == 1)
                {
                    // a quadr. residue mod p
                    v = P.Add(ONE); // v = p+1
                    v = v.ShiftRight(2); // v = v/4
                    return X.ModPow(v, P); // return a^v mod p
                }
                throw new ArgumentException("No quadratic residue: " + X + ", " + P);
            }

            long t = 0;

            // initialization
            // compute k and s, where p = 2^s (2k+1) +1

            BigInteger k = P.Subtract(ONE); // k = p-1
            long s = 0;
            while (!k.TestBit(0))
            { // while k is even
                s++; // s = s+1
                k = k.ShiftRight(1); // k = k/2
            }

            k = k.Subtract(ONE); // k = k - 1
            k = k.ShiftRight(1); // k = k/2

            // initial values
            BigInteger r = X.ModPow(k, P); // r = a^k mod p

            BigInteger n = r.Multiply(r).Remainder(P); // n = r^2 % p
            n = n.Multiply(X).Remainder(P); // n = n * a % p
            r = r.Multiply(X).Remainder(P); // r = r * a %p

            if (n.Equals(ONE))
            {
                return r;
            }

            // non-quadratic residue
            BigInteger z = TWO; // z = 2
            while (Jacobi(z, P) == 1)
            {
                // while z quadratic residue
                z = z.Add(ONE); // z = z + 1
            }

            v = k;
            v = v.Multiply(TWO); // v = 2k
            v = v.Add(ONE); // v = 2k + 1
            BigInteger c = z.ModPow(v, P); // c = z^v mod p

            // iteration
            while (n.CompareTo(ONE) == 1)
            { // n > 1
                k = n; // k = n
                t = s; // t = s
                s = 0;

                while (!k.Equals(ONE))
                { // k != 1
                    k = k.Multiply(k).Mod(P); // k = k^2 % p
                    s++; // s = s + 1
                }

                t -= s; // t = t - s
                if (t == 0)
                {
                    throw new ArgumentException("No quadratic residue: " + X + ", " + P);
                }

                v = ONE;
                for (long i = 0; i < t - 1; i++)
                {
                    v = v.ShiftLeft(1); // v = 1 * 2^(t - 1)
                }
                c = c.ModPow(v, P); // c = c^v mod p
                r = r.Multiply(c).Remainder(P); // r = r * c % p
                c = c.Multiply(c).Remainder(P); // c = c^2 % p
                n = n.Multiply(c).Mod(P); // n = n * c % p
            }
            return r;
        }

        /// <summary>
        /// Create a random BigInteger
        /// </summary>
        /// 
        /// <param name="UpperBound">The upper bound</param>
        /// <param name="SecRnd">An instance of the SecureRandom class</param>
        /// 
        /// <returns>A random BigInteger</returns>
        public static BigInteger Randomize(BigInteger UpperBound, SecureRandom SecRnd)
        {
            int blen = UpperBound.BitLength;
            BigInteger randomNum = BigInteger.ValueOf(0);

            if (SecRnd == null)
                SecRnd = m_secRnd != null ? m_secRnd : new SecureRandom();

            for (int i = 0; i < 20; i++)
            {
                randomNum = new BigInteger(blen, SecRnd);
                if (randomNum.CompareTo(UpperBound) < 0)
                    return randomNum;
            }

            return randomNum.Mod(UpperBound);
        }

        /// <summary>
        /// Extract the truncated square root of a BigInteger
        /// </summary>
        /// 
        /// <param name="X">A value out of which we extract the square root</param>
        /// 
        /// <returns>Returns the truncated square root of <c>a</c></returns>
        public static BigInteger SquareRoot(BigInteger X)
        {
            int bl;
            BigInteger result, remainder, b;

            if (X.CompareTo(ZERO) < 0)
                throw new ArithmeticException("Cannot extract root of negative number" + X + "!");

            bl = X.BitLength;
            result = ZERO;
            remainder = ZERO;

            // if the bit length is odd then extra step
            if ((bl & 1) != 0)
            {
                result = result.Add(ONE);
                bl--;
            }

            while (bl > 0)
            {
                remainder = remainder.Multiply(FOUR);
                remainder = remainder.Add(BigInteger.ValueOf((X.TestBit(--bl) ? 2 : 0) + (X.TestBit(--bl) ? 1 : 0)));
                b = result.Multiply(FOUR).Add(ONE);
                result = result.Multiply(TWO);

                if (remainder.CompareTo(b) != -1)
                {
                    result = result.Add(ONE);
                    remainder = remainder.Subtract(b);
                }
            }

            return result;
        }

        /// <summary>
        /// BKM Algorithm to calculate logarithms to the base 2
        /// </summary>
        /// 
        /// <param name="X"> double value with 1&lt;= arg&lt;= 4.768462058</param>
        /// 
        /// <returns>Returns log_2(arg)</returns>
        private static double LogBKM(double X)
        {
            double[] ae = // A_e[k] = log_2 (1 + 0.5^k)
            {
                1.0000000000000000000000000000000000000000000000000000000000000000000000000000,
                0.5849625007211561814537389439478165087598144076924810604557526545410982276485,
                0.3219280948873623478703194294893901758648313930245806120547563958159347765589,
                0.1699250014423123629074778878956330175196288153849621209115053090821964552970,
                0.0874628412503394082540660108104043540112672823448206881266090643866965081686,
                0.0443941193584534376531019906736094674630459333742491317685543002674288465967,
                0.0223678130284545082671320837460849094932677948156179815932199216587899627785,
                0.0112272554232541203378805844158839407281095943600297940811823651462712311786,
                0.0056245491938781069198591026740666017211096815383520359072957784732489771013,
                0.0028150156070540381547362547502839489729507927389771959487826944878598909400,
                0.0014081943928083889066101665016890524233311715793462235597709051792834906001,
                0.0007042690112466432585379340422201964456668872087249334581924550139514213168,
                0.0003521774803010272377989609925281744988670304302127133979341729842842377649,
                0.0001760994864425060348637509459678580940163670081839283659942864068257522373,
                0.0000880524301221769086378699983597183301490534085738474534831071719854721939,
                0.0000440268868273167176441087067175806394819146645511899503059774914593663365,
                0.0000220136113603404964890728830697555571275493801909791504158295359319433723,
                0.0000110068476674814423006223021573490183469930819844945565597452748333526464,
                0.0000055034343306486037230640321058826431606183125807276574241540303833251704,
                0.0000027517197895612831123023958331509538486493412831626219340570294203116559,
                0.0000013758605508411382010566802834037147561973553922354232704569052932922954,
                0.0000006879304394358496786728937442939160483304056131990916985043387874690617,
                0.0000003439652607217645360118314743718005315334062644619363447395987584138324,
                0.0000001719826406118446361936972479533123619972434705828085978955697643547921,
                0.0000000859913228686632156462565208266682841603921494181830811515318381744650,
                0.0000000429956620750168703982940244684787907148132725669106053076409624949917,
                0.0000000214978311976797556164155504126645192380395989504741781512309853438587,
                0.0000000107489156388827085092095702361647949603617203979413516082280717515504,
                0.0000000053744578294520620044408178949217773318785601260677517784797554422804,
                0.0000000026872289172287079490026152352638891824761667284401180026908031182361,
                0.0000000013436144592400232123622589569799954658536700992739887706412976115422,
                0.0000000006718072297764289157920422846078078155859484240808550018085324187007,
                0.0000000003359036149273187853169587152657145221968468364663464125722491530858,
                0.0000000001679518074734354745159899223037458278711244127245990591908996412262,
                0.0000000000839759037391617577226571237484864917411614198675604731728132152582,
                0.0000000000419879518701918839775296677020135040214077417929807824842667285938,
                0.0000000000209939759352486932678195559552767641474249812845414125580747434389,
                0.0000000000104969879676625344536740142096218372850561859495065136990936290929,
                0.0000000000052484939838408141817781356260462777942148580518406975851213868092,
                0.0000000000026242469919227938296243586262369156865545638305682553644113887909,
                0.0000000000013121234959619935994960031017850191710121890821178731821983105443,
                0.0000000000006560617479811459709189576337295395590603644549624717910616347038,
                0.0000000000003280308739906102782522178545328259781415615142931952662153623493,
                0.0000000000001640154369953144623242936888032768768777422997704541618141646683,
                0.0000000000000820077184976595619616930350508356401599552034612281802599177300,
                0.0000000000000410038592488303636807330652208397742314215159774270270147020117,
                0.0000000000000205019296244153275153381695384157073687186580546938331088730952,
                0.0000000000000102509648122077001764119940017243502120046885379813510430378661,
                0.0000000000000051254824061038591928917243090559919209628584150482483994782302,
                0.0000000000000025627412030519318726172939815845367496027046030028595094737777,
                0.0000000000000012813706015259665053515049475574143952543145124550608158430592,
                0.0000000000000006406853007629833949364669629701200556369782295210193569318434,
                0.0000000000000003203426503814917330334121037829290364330169106716787999052925,
                0.0000000000000001601713251907458754080007074659337446341494733882570243497196,
                0.0000000000000000800856625953729399268240176265844257044861248416330071223615,
                0.0000000000000000400428312976864705191179247866966320469710511619971334577509,
                0.0000000000000000200214156488432353984854413866994246781519154793320684126179,
                0.0000000000000000100107078244216177339743404416874899847406043033792202127070,
                0.0000000000000000050053539122108088756700751579281894640362199287591340285355,
                0.0000000000000000025026769561054044400057638132352058574658089256646014899499,
                0.0000000000000000012513384780527022205455634651853807110362316427807660551208,
                0.0000000000000000006256692390263511104084521222346348012116229213309001913762,
                0.0000000000000000003128346195131755552381436585278035120438976487697544916191,
                0.0000000000000000001564173097565877776275512286165232838833090480508502328437,
                0.0000000000000000000782086548782938888158954641464170239072244145219054734086,
                0.0000000000000000000391043274391469444084776945327473574450334092075712154016,
                0.0000000000000000000195521637195734722043713378812583900953755962557525252782,
                0.0000000000000000000097760818597867361022187915943503728909029699365320287407,
                0.0000000000000000000048880409298933680511176764606054809062553340323879609794,
                0.0000000000000000000024440204649466840255609083961603140683286362962192177597,
                0.0000000000000000000012220102324733420127809717395445504379645613448652614939,
                0.0000000000000000000006110051162366710063906152551383735699323415812152114058,
                0.0000000000000000000003055025581183355031953399739107113727036860315024588989,
                0.0000000000000000000001527512790591677515976780735407368332862218276873443537,
                0.0000000000000000000000763756395295838757988410584167137033767056170417508383,
                0.0000000000000000000000381878197647919378994210346199431733717514843471513618,
                0.0000000000000000000000190939098823959689497106436628681671067254111334889005,
                0.0000000000000000000000095469549411979844748553534196582286585751228071408728,
                0.0000000000000000000000047734774705989922374276846068851506055906657137209047,
                0.0000000000000000000000023867387352994961187138442777065843718711089344045782,
                0.0000000000000000000000011933693676497480593569226324192944532044984865894525,
                0.0000000000000000000000005966846838248740296784614396011477934194852481410926,
                0.0000000000000000000000002983423419124370148392307506484490384140516252814304,
                0.0000000000000000000000001491711709562185074196153830361933046331030629430117,
                0.0000000000000000000000000745855854781092537098076934460888486730708440475045,
                0.0000000000000000000000000372927927390546268549038472050424734256652501673274,
                0.0000000000000000000000000186463963695273134274519237230207489851150821191330,
                0.0000000000000000000000000093231981847636567137259618916352525606281553180093,
                0.0000000000000000000000000046615990923818283568629809533488457973317312233323,
                0.0000000000000000000000000023307995461909141784314904785572277779202790023236,
                0.0000000000000000000000000011653997730954570892157452397493151087737428485431,
                0.0000000000000000000000000005826998865477285446078726199923328593402722606924,
                0.0000000000000000000000000002913499432738642723039363100255852559084863397344,
                0.0000000000000000000000000001456749716369321361519681550201473345138307215067,
                0.0000000000000000000000000000728374858184660680759840775119123438968122488047,
                0.0000000000000000000000000000364187429092330340379920387564158411083803465567,
                0.0000000000000000000000000000182093714546165170189960193783228378441837282509,
                0.0000000000000000000000000000091046857273082585094980096891901482445902524441,
                0.0000000000000000000000000000045523428636541292547490048446022564529197237262,
                0.0000000000000000000000000000022761714318270646273745024223029238091160103901};

            int n = 53;
            double x = 1;
            double y = 0;
            double z;
            double s = 1;
            int k;

            for (k = 0; k < n; k++)
            {
                z = x + x * s;
                if (z <= X)
                {
                    x = z;
                    y += ae[k];
                }
                s *= 0.5;
            }
            return y;
        }
        #endregion
    }
}
