#region Directives
using System;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric 
{
    /// <summary>
    /// Static library that provides all operations related with division and modular arithmetic to <see cref="BigInteger"/>.
    /// <para>Some methods are provided in both mutable and immutable way.</para>
    /// 
    /// <description>There are several variants provided listed below:</description>
    /// <list type="bullet">
    /// <item><description>BigInteger Division and Remainder operations</description></item>
    /// <item><description>Modular exponentiation between BigInteger</description></item>
    /// <item><description>Modular inverse of a BigInteger numbers</description>/></item>
    /// <item><description>BigInteger division and remainder by int</description></item>
    /// </list>
    /// </summary>
    internal sealed class Division
    {
        #region Constructor
        private Division()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Divides the array 'a' by the array 'b' and gets the quotient and the remainder.
        /// <para>Implements the Knuth's division algorithm. See D. Knuth, The Art of Computer Programming, 
        /// vol. 2. Steps D1-D8 correspond the steps in the algorithm description.</para>
        /// </summary>
        /// 
        /// <param name="Quotient">The quotient</param>
        /// <param name="QuotientLen">The quotient's length</param>
        /// <param name="X">The dividend</param>
        /// <param name="XLen">The dividend's length</param>
        /// <param name="Y">The divisor</param>
        /// <param name="YLength">The divisor's length</param>
        /// 
        /// <returns>eturn the remainder</returns>
        internal static int[] Divide(int[] Quotient, int QuotientLen, int[] X, int XLen, int[] Y, int YLength)
        {
            int[] normA = new int[XLen + 1]; // the normalized dividend
            // an extra byte is needed for correct shift
            int[] normB = new int[YLength + 1]; // the normalized divisor;
            int normBLength = YLength;

            // Step D1: normalize a and b and put the results to a1 and b1 the
            // normalized divisor's first digit must be >= 2^31
            int divisorShift = IntUtils.NumberOfLeadingZeros(Y[YLength - 1]);
            if (divisorShift != 0)
            {
                BitLevel.ShiftLeft(normB, Y, 0, divisorShift);
                BitLevel.ShiftLeft(normA, X, 0, divisorShift);
            }
            else
            {
                Array.Copy(X, 0, normA, 0, XLen);
                Array.Copy(Y, 0, normB, 0, YLength);
            }
            int firstDivisorDigit = normB[normBLength - 1];
            // Step D2: set the quotient index
            int i = QuotientLen - 1;
            int j = XLen;

            while (i >= 0)
            {
                // Step D3: calculate a guess digit guessDigit
                int guessDigit = 0;

                if (normA[j] == firstDivisorDigit)
                {
                    // set guessDigit to the largest unsigned int value
                    guessDigit = -1;
                }
                else
                {
                    long product = (((normA[j] & 0xffffffffL) << 32) + (normA[j - 1] & 0xffffffffL));
                    long res = Division.DivideLongByInt(product, firstDivisorDigit);
                    guessDigit = (int)res; // the quotient of divideLongByInt
                    int rem = (int)(res >> 32); // the remainder of
                    // divideLongByInt
                    // decrease guessDigit by 1 while leftHand > rightHand
                    if (guessDigit != 0)
                    {
                        long leftHand = 0;
                        long rightHand = 0;
                        bool rOverflowed = false;
                        guessDigit++; // to have the proper value in the loop
                        // below
                        do
                        {
                            guessDigit--;
                            if (rOverflowed)
                                break;

                            // leftHand always fits in an unsigned long
                            leftHand = (guessDigit & 0xffffffffL) * (normB[normBLength - 2] & 0xffffffffL);
                            // rightHand can overflow; in this case the loop
                            // condition will be true in the next step of the loop
                            rightHand = ((long)rem << 32) + (normA[j - 2] & 0xffffffffL);
                            long longR = (rem & 0xffffffffL) + (firstDivisorDigit & 0xffffffffL);
                            // checks that longR does not fit in an unsigned int;
                            // this ensures that rightHand will overflow unsigned long in the next step
                            if (IntUtils.NumberOfLeadingZeros((int)IntUtils.URShift(longR, 32)) < 32)
                                rOverflowed = true;
                            else
                                rem = (int)longR;

                        } while ((leftHand ^ Int64.MinValue) > (rightHand ^ Int64.MinValue));
                    }
                }
                // Step D4: multiply normB by guessDigit and subtract the production from normA.
                if (guessDigit != 0)
                {
                    int borrow = Division.MultiplyAndSubtract(normA, j - normBLength, normB, normBLength, guessDigit);
                    // Step D5: check the borrow
                    if (borrow != 0)
                    {
                        // Step D6: compensating addition
                        guessDigit--;
                        long carry = 0;
                        for (int k = 0; k < normBLength; k++)
                        {
                            carry += (normA[j - normBLength + k] & 0xffffffffL) + (normB[k] & 0xffffffffL);
                            normA[j - normBLength + k] = (int)carry;
                            carry = IntUtils.URShift(carry, 32);
                        }
                    }
                }
                if (Quotient != null)
                {
                    Quotient[i] = guessDigit;
                }
                // Step D7
                j--;
                i--;
            }
            // Step D8: we got the remainder in normA. Denormalize it as needed
            if (divisorShift != 0)
            {
                // reuse normB
                BitLevel.ShiftRight(normB, normBLength, normA, 0, divisorShift);
                return normB;
            }
            Array.Copy(normA, 0, normB, 0, YLength);

            return normA;
        }

        /// <summary>
        /// Computes the quotient and the remainder after a division by an int number
        /// </summary>
        /// 
        /// <param name="Value">The BigInteger dividend</param>
        /// <param name="Divisor">The divisor</param>
        /// <param name="DivisorSign">The divisors sign</param>
        /// 
        /// <returns>Returns an array of the form <c>[quotient, remainder]</c></returns>
        internal static BigInteger[] DivideAndRemainderByInteger(BigInteger Value, int Divisor, int DivisorSign)
        {
            // res[0] is a quotient and res[1] is a remainder:
            int[] valDigits = Value._digits;
            int valLen = Value._numberLength;
            int valSign = Value._sign;
            if (valLen == 1)
            {
                long a = (valDigits[0] & 0xffffffffL);
                long b = (Divisor & 0xffffffffL);
                long quo = a / b;
                long rem = a % b;
                if (valSign != DivisorSign)
                {
                    quo = -quo;
                }
                if (valSign < 0)
                {
                    rem = -rem;
                }
                return new BigInteger[] { BigInteger.ValueOf(quo),
                    BigInteger.ValueOf(rem) };
            }
            int quotientLength = valLen;
            int quotientSign = ((valSign == DivisorSign) ? 1 : -1);
            int[] quotientDigits = new int[quotientLength];
            int[] remainderDigits;
            remainderDigits = new int[] { Division.DivideArrayByInt(
                quotientDigits, valDigits, valLen, Divisor) };
            BigInteger result0 = new BigInteger(quotientSign, quotientLength,
                    quotientDigits);
            BigInteger result1 = new BigInteger(valSign, 1, remainderDigits);
            result0.CutOffLeadingZeroes();
            result1.CutOffLeadingZeroes();
            return new BigInteger[] { result0, result1 };
        }

        /// <summary>
        /// Divides an array by an integer value. Implements the Knuth's division algorithm.
        /// <para>See D. Knuth, The Art of Computer Programming, vol. 2.</para>
        /// </summary>
        /// 
        /// <param name="Destination">The quotient</param>
        /// <param name="Source">The dividend</param>
        /// <param name="SourceLength">The length of the dividend</param>
        /// <param name="Divisor">The divisor</param>
        /// 
        /// <returns>Returns the remainder</returns>
        internal static int DivideArrayByInt(int[] Destination, int[] Source, int SourceLength, int Divisor)
        {
            long rem = 0;
            long bLong = Divisor & 0xffffffffL;

            for (int i = SourceLength - 1; i >= 0; i--)
            {
                long temp = (rem << 32) | (Source[i] & 0xffffffffL);
                long quot;
                if (temp >= 0)
                {
                    quot = (temp / bLong);
                    rem = (temp % bLong);
                }
                else
                {
                    // make the dividend positive shifting it right by 1 bit then
                    // get the quotient an remainder and correct them properly
                    long aPos = IntUtils.URShift(temp, 1);
                    long bPos = IntUtils.URShift(Divisor, 1);
                    quot = aPos / bPos;
                    rem = aPos % bPos;
                    // double the remainder and add 1 if a is odd
                    rem = (rem << 1) + (temp & 1);
                    if ((Divisor & 1) != 0)
                    {
                        // the divisor is odd
                        if (quot <= rem)
                        {
                            rem -= quot;
                        }
                        else
                        {
                            if (quot - rem <= bLong)
                            {
                                rem += bLong - quot;
                                quot -= 1;
                            }
                            else
                            {
                                rem += (bLong << 1) - quot;
                                quot -= 2;
                            }
                        }
                    }
                }
                Destination[i] = (int)(quot & 0xffffffffL);
            }

            return (int)rem;
        }

        /// <summary>
        /// Performs modular exponentiation using the Montgomery Reduction.
        /// <para>It requires that all parameters be positive and the modulus be even.
        /// Based on theThe square and multiply algorithm and the Montgomery Reduction 
        /// C. K. Koc - Montgomery Reduction with Even Modulus.
        /// The square and multiply algorithm and the Montgomery Reduction.
        /// ar.org.fitc.ref "C. K. Koc - Montgomery Reduction with Even Modulus"
        /// </para>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger</param>
        /// <param name="Y">The Exponent</param>
        /// <param name="Modulus">The Modulus</param>
        /// 
        /// <returns><c>x1 + q * y</c></returns>
        internal static BigInteger EvenModPow(BigInteger X, BigInteger Y, BigInteger Modulus)
        {
            // PRE: (base > 0), (exponent > 0), (modulus > 0) and (modulus even)
            // STEP 1: Obtain the factorization 'modulus'= q * 2^j.
            int j = Modulus.LowestSetBit;
            BigInteger q = Modulus.ShiftRight(j);

            // STEP 2: Compute x1 := base^exponent (mod q).
            BigInteger x1 = OddModPow(X, Y, q);

            // STEP 3: Compute x2 := base^exponent (mod 2^j).
            BigInteger x2 = Pow2ModPow(X, Y, j);

            // STEP 4: Compute q^(-1) (mod 2^j) and y := (x2-x1) * q^(-1) (mod 2^j)
            BigInteger qInv = ModPow2Inverse(q, j);
            BigInteger y = (x2.Subtract(x1)).Multiply(qInv);
            InplaceModPow2(y, j);

            if (y._sign < 0)
                y = y.Add(BigInteger.GetPowerOfTwo(j));
            
            // STEP 5: Compute and return: x1 + q * y
            return x1.Add(q.Multiply(y));
        }

        /// <summary>
        /// Return the greatest common divisor of X and Y
        /// </summary>
        /// 
        /// <param name="X">Operand 1, must be greater than zero</param>
        /// <param name="Y">Operand 2, must be greater than zero</param>
        /// 
        /// <returns>Returns <c>GCD(X, Y)</c></returns>
        internal static BigInteger GcdBinary(BigInteger X, BigInteger Y)
        {
            // Divide both number the maximal possible times by 2 without rounding * gcd(2*a, 2*b) = 2 * gcd(a,b)
            int lsb1 = X.LowestSetBit;
            int lsb2 = Y.LowestSetBit;
            int pow2Count = System.Math.Min(lsb1, lsb2);

            BitLevel.InplaceShiftRight(X, lsb1);
            BitLevel.InplaceShiftRight(Y, lsb2);
            BigInteger swap;

            // I want op2 > op1
            if (X.CompareTo(Y) == BigInteger.GREATER)
            {
                swap = X;
                X = Y;
                Y = swap;
            }

            do
            { // INV: op2 >= op1 && both are odd unless op1 = 0

                // Optimization for small operands (op2.bitLength() < 64) implies by INV (op1.bitLength() < 64)
                if ((Y._numberLength == 1) || ((Y._numberLength == 2) && (Y._digits[1] > 0)))
                {
                    Y = BigInteger.ValueOf(Division.GcdBinary(X.ToInt64(), Y.ToInt64()));
                    break;
                }

                // Implements one step of the Euclidean algorithm
                // To reduce one operand if it's much smaller than the other one
                if (Y._numberLength > X._numberLength * 1.2)
                {
                    Y = Y.Remainder(X);

                    if (Y.Signum() != 0)
                        BitLevel.InplaceShiftRight(Y, Y.LowestSetBit);
                }
                else
                {

                    // Use Knuth's algorithm of successive subtract and shifting
                    do
                    {
                        Elementary.InplaceSubtract(Y, X); // both are odd
                        BitLevel.InplaceShiftRight(Y, Y.LowestSetBit); // op2 is even
                    } while (Y.CompareTo(X) >= BigInteger.EQUALS);
                }
                // now op1 >= op2
                swap = Y;
                Y = X;
                X = swap;
            } while (X._sign != 0);

            return Y.ShiftLeft(pow2Count);
        }

        /// <summary>
        /// Performs the same as GcdBinary(BigInteger, BigInteger)}, but with numbers of 63 bits, 
        /// represented in positives values of long type.
        /// </summary>
        /// 
        /// <param name="X">A positive number</param>
        /// <param name="Y">A positive number></param>
        /// 
        /// <returns>Returns <c>Gcd(X, Y)</c></returns>
        internal static long GcdBinary(long X, long Y)
        {
            // (op1 > 0) and (op2 > 0)
            int lsb1 = IntUtils.NumberOfTrailingZeros(X);
            int lsb2 = IntUtils.NumberOfTrailingZeros(Y);
            int pow2Count = System.Math.Min(lsb1, lsb2);

            if (lsb1 != 0)
                X = IntUtils.URShift(X, lsb1);
            if (lsb2 != 0)
                Y = IntUtils.URShift(Y, lsb2);
            
            do
            {
                if (X >= Y)
                {
                    X -= Y;
                    X = IntUtils.URShift(X, IntUtils.NumberOfTrailingZeros(X));
                }
                else
                {
                    Y -= X;
                    Y = IntUtils.URShift(Y, IntUtils.NumberOfTrailingZeros(Y));
                }
            } while (X != 0);

            return (Y << pow2Count);
        }

        /// <summary>
        /// Performs <c>X = X Mod (2<sup>N</sup>)</c>
        /// </summary>
        /// <param name="X">A positive number, it will store the result</param>
        /// <param name="N">A positive exponent of 2</param>
        internal static void InplaceModPow2(BigInteger X, int N)
        {
            // PRE: (x > 0) and (n >= 0)
            int fd = N >> 5;
            int leadingZeros;

            if ((X._numberLength < fd) || (X.BitLength <= N))
            {
                return;
            }
            leadingZeros = 32 - (N & 31);
            X._numberLength = fd + 1;
            X._digits[fd] &= (leadingZeros < 32) ? (IntUtils.URShift(-1, leadingZeros)) : 0;
            X.CutOffLeadingZeroes();
        }

        /// <summary>
        /// Calculates x.modInverse(p) Based on: Savas, E; Koc, C "The Montgomery Modular Inverse - Revised"
        /// </summary>
        /// 
        /// <param name="X">BigInteger X</param>
        /// <param name="P">BigInteger P</param>
        /// 
        /// <returns>Returns <c>1/X Mod M</c></returns>
        internal static BigInteger ModInverseMontgomery(BigInteger X, BigInteger P)
        {
            // ZERO hasn't inverse
            if (X._sign == 0)
                throw new ArithmeticException("BigInteger not invertible!");

            // montgomery inverse require even modulo
            if (!P.TestBit(0))
                return ModInverseLorencz(X, P);

            int m = P._numberLength * 32;
            // PRE: a \in [1, p - 1]
            BigInteger u, v, r, s;
            u = P.Copy();  // make copy to use inplace method
            v = X.Copy();

            int max = System.Math.Max(v._numberLength, u._numberLength);
            r = new BigInteger(1, 1, new int[max + 1]);
            s = new BigInteger(1, 1, new int[max + 1]);
            s._digits[0] = 1;

            int k = 0;
            int lsbu = u.LowestSetBit;
            int lsbv = v.LowestSetBit;
            int toShift;

            if (lsbu > lsbv)
            {
                BitLevel.InplaceShiftRight(u, lsbu);
                BitLevel.InplaceShiftRight(v, lsbv);
                BitLevel.InplaceShiftLeft(r, lsbv);
                k += lsbu - lsbv;
            }
            else
            {
                BitLevel.InplaceShiftRight(u, lsbu);
                BitLevel.InplaceShiftRight(v, lsbv);
                BitLevel.InplaceShiftLeft(s, lsbu);
                k += lsbv - lsbu;
            }

            r._sign = 1;
            while (v.Signum() > 0)
            {
                // INV v >= 0, u >= 0, v odd, u odd (except last iteration when v is even (0))

                while (u.CompareTo(v) > BigInteger.EQUALS)
                {
                    Elementary.InplaceSubtract(u, v);
                    toShift = u.LowestSetBit;
                    BitLevel.InplaceShiftRight(u, toShift);
                    Elementary.InplaceAdd(r, s);
                    BitLevel.InplaceShiftLeft(s, toShift);
                    k += toShift;
                }

                while (u.CompareTo(v) <= BigInteger.EQUALS)
                {
                    Elementary.InplaceSubtract(v, u);

                    if (v.Signum() == 0)
                        break;

                    toShift = v.LowestSetBit;
                    BitLevel.InplaceShiftRight(v, toShift);
                    Elementary.InplaceAdd(s, r);
                    BitLevel.InplaceShiftLeft(r, toShift);
                    k += toShift;
                }
            }

            // in u is stored the gcd
            if (!u.IsOne())
                throw new ArithmeticException("BigInteger not invertible.");

            if (r.CompareTo(P) >= BigInteger.EQUALS)
                Elementary.InplaceSubtract(r, P);

            r = P.Subtract(r);

            // Have pair: ((BigInteger)r, (Integer)k) where r == a^(-1) * 2^k mod (module)		
            int n1 = CalcN(P);
            if (k > m)
            {
                r = MonPro(r, BigInteger.One, P, n1);
                k = k - m;
            }

            r = MonPro(r, BigInteger.GetPowerOfTwo(m - k), P, n1);

            return r;
        }

        /// <summary>
        /// Multiplies an array by int and subtracts it from a subarray of another array
        /// </summary>
        /// 
        /// <param name="X">The array to subtract from</param>
        /// <param name="Start">The start element of the subarray of X</param>
        /// <param name="Y">The array to be multiplied and subtracted</param>
        /// <param name="YLength">The length of Y</param>
        /// <param name="Multiplier">The multiplier of Y</param>
        /// 
        /// <returns>Returns the carry element of subtraction</returns>
        internal static int MultiplyAndSubtract(int[] X, int Start, int[] Y, int YLength, int Multiplier)
        {
            long carry0 = 0;
            long carry1 = 0;

            for (int i = 0; i < YLength; i++)
            {
                carry0 = Multiplication.UnsignedMultAddAdd(Y[i], Multiplier, (int)carry0, 0);
                carry1 = (X[Start + i] & 0xffffffffL) - (carry0 & 0xffffffffL) + carry1;
                X[Start + i] = (int)carry1;
                carry1 >>= 32; // -1 or 0
                carry0 = IntUtils.URShift(carry0, 32);
            }

            carry1 = (X[Start + YLength] & 0xffffffffL) - carry0 + carry1;
            X[Start + YLength] = (int)carry1;

            return (int)(carry1 >> 32); // -1 or 0
        }

        /// <summary>
        /// Performs modular exponentiation using the Montgomery Reduction.
        /// <para>It requires that all parameters be positive and the modulus be odd. </para>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger</param>
        /// <param name="Y">The exponent</param>
        /// <param name="Modulus">The modulus</param>
        /// 
        /// <returns><c>(modulus[0]^(-1)) (mod 2^32)</c></returns>
        internal static BigInteger OddModPow(BigInteger X, BigInteger Y, BigInteger Modulus)
        {
            // PRE: (base > 0), (exponent > 0), (modulus > 0) and (odd modulus)
            int k = (Modulus._numberLength << 5); // r = 2^k
            // n-residue of base [base * r (mod modulus)]
            BigInteger a2 = X.ShiftLeft(k).Mod(Modulus);
            // n-residue of base [1 * r (mod modulus)]
            BigInteger x2 = BigInteger.GetPowerOfTwo(k).Mod(Modulus);
            BigInteger res;
            // Compute (modulus[0]^(-1)) (mod 2^32) for odd modulus

            int n2 = CalcN(Modulus);

            if (Modulus._numberLength == 1)
                res = SquareAndMultiply(x2, a2, Y, Modulus, n2);
            else
                res = SlidingWindow(x2, a2, Y, Modulus, n2);

            return MonPro(res, BigInteger.One, Modulus, n2);
        }

        /// <summary>
        /// Divides a BigInteger by a signed int and returns the remainder
        /// </summary>
        /// 
        /// <param name="X">The BigInteger to be divided. Must be non-negative</param>
        /// <param name="Divisor">A signed integer</param>
        /// 
        /// <returns>Returns Divide % Divisor</returns>
        internal static int Remainder(BigInteger X, int Divisor)
        {
            return RemainderArrayByInt(X._digits, X._numberLength, Divisor);
        }

        /// <summary>
        /// Divides an array by an integer value. Implements the Knuth's division
        /// algorithm. See D. Knuth, The Art of Computer Programming, vol. 2.
        /// </summary>
        /// 
        /// <param name="Source">The dividend</param>
        /// <param name="SourceLength">The length of the dividend</param>
        /// <param name="Divisor">The divisor</param>
        /// 
        /// <returns>Returns the remainder</returns>
        internal static int RemainderArrayByInt(int[] Source, int SourceLength, int Divisor)
        {

            long result = 0;

            for (int i = SourceLength - 1; i >= 0; i--)
            {
                long temp = (result << 32) + (Source[i] & 0xffffffffL);
                long res = DivideLongByInt(temp, Divisor);
                result = (int)(res >> 32);
            }
            return (int)result;
        }
        #endregion

        #region Private Methods
        private static int CalcN(BigInteger X)
        {
            // calculate the first digit of the inverse
            long m0 = X._digits[0] & 0xFFFFFFFFL;
            long n2 = 1L; // this is a'[0]
            long powerOfTwo = 2L;

            do
            {
                if (((m0 * n2) & powerOfTwo) != 0)
                    n2 |= powerOfTwo;

                powerOfTwo <<= 1;
            } while (powerOfTwo < 0x100000000L);

            n2 = -n2;

            return (int)(n2 & 0xFFFFFFFFL);
        }

        private static long DivideLongByInt(long X, int Y)
        {
            // divides an unsigned long X by an unsigned int Y
            // 
            long quot;
            long rem;
            long bLong = Y & 0xffffffffL;

            if (X >= 0)
            {
                quot = (X / bLong);
                rem = (X % bLong);
            }
            else
            {
                /*
                 * Make the dividend positive shifting it right by 1 bit then get
                 * the quotient an remainder and correct them properly
                 */
                long aPos = IntUtils.URShift(X, 1);
                long bPos = IntUtils.URShift(Y, 1);
                quot = aPos / bPos;
                rem = aPos % bPos;
                // double the remainder and add 1 if a is odd
                rem = (rem << 1) + (X & 1);

                if ((Y & 1) != 0)
                { // the divisor is odd
                    if (quot <= rem)
                    {
                        rem -= quot;
                    }
                    else
                    {
                        if (quot - rem <= bLong)
                        {
                            rem += bLong - quot;
                            quot -= 1;
                        }
                        else
                        {
                            rem += (bLong << 1) - quot;
                            quot -= 2;
                        }
                    }
                }
            }
            return (rem << 32) | (quot & 0xffffffffL);
        }

        private static BigInteger FinalSubtraction(int[] Result, BigInteger Modulus)
        {
            // Performs the  reduction of the Montgomery algorithm
            // skipping leading zeros
            int modulusLen = Modulus._numberLength;
            bool doSub = Result[modulusLen] != 0;

            if (!doSub)
            {
                int[] modulusDigits = Modulus._digits;
                doSub = true;
                for (int i = modulusLen - 1; i >= 0; i--)
                {
                    if (Result[i] != modulusDigits[i])
                    {
                        doSub = (Result[i] != 0) && ((Result[i] & 0xFFFFFFFFL) > (modulusDigits[i] & 0xFFFFFFFFL));
                        break;
                    }
                }
            }

            BigInteger result = new BigInteger(1, modulusLen + 1, Result);

            // if (res >= modulusDigits) compute (res - modulusDigits)
            if (doSub)
                Elementary.InplaceSubtract(result, Modulus);

            result.CutOffLeadingZeroes();

            return result;
        }

        private static int HowManyIterations(BigInteger X, int N)
        {
            // Calculate how many iteration of Lorencz's algorithm would perform the same operation
            int i = N - 1;
            if (X._sign > 0)
            {
                while (!X.TestBit(i))
                    i--;

                return N - 1 - i;
            }
            else
            {
                while (X.TestBit(i))
                    i--;

                return N - 1 - System.Math.Max(i, X.LowestSetBit);
            }
        }

        private static bool IsPowerOfTwo(BigInteger X, int Y)
        {
            // return X == Abs(2^exp)
            bool result = false;
            result = (Y >> 5 == X._numberLength - 1) && (X._digits[X._numberLength - 1] == 1 << (Y & 31));

            if (result)
            {
                for (int i = 0; result && i < X._numberLength - 1; i++)
                    result = X._digits[i] == 0;
            }

            return result;
        }

        private static BigInteger ModInverseLorencz(BigInteger X, BigInteger Modulo)
        {
            // Based on "New Algorithm for Classical Modular Inverse" Róbert Lórencz. LNCS 2523 (2002)
            // PRE: a is coprime with modulo, a < modulo
            int max = System.Math.Max(X._numberLength, Modulo._numberLength);
            int[] uDigits = new int[max + 1]; // enough place to make all the inplace operation
            int[] vDigits = new int[max + 1];
            Array.Copy(Modulo._digits, 0, uDigits, 0, Modulo._numberLength);
            Array.Copy(X._digits, 0, vDigits, 0, X._numberLength);

            BigInteger u = new BigInteger(Modulo._sign, Modulo._numberLength, uDigits);
            BigInteger v = new BigInteger(X._sign, X._numberLength, vDigits);
            BigInteger r = new BigInteger(0, 1, new int[max + 1]); // BigInteger.ZERO;
            BigInteger s = new BigInteger(1, 1, new int[max + 1]);
            s._digits[0] = 1;
            // r == 0 && s == 1, but with enough place

            int coefU = 0, coefV = 0;
            int n = Modulo.BitLength;
            int k;

            while (!IsPowerOfTwo(u, coefU) && !IsPowerOfTwo(v, coefV))
            {
                // modification of original algorithm: I calculate how many times the algorithm will enter in the same branch of if
                k = HowManyIterations(u, n);
                if (k != 0)
                {
                    BitLevel.InplaceShiftLeft(u, k);
                    if (coefU >= coefV)
                    {
                        BitLevel.InplaceShiftLeft(r, k);
                    }
                    else
                    {
                        BitLevel.InplaceShiftRight(s, System.Math.Min(coefV - coefU, k));

                        if (k - (coefV - coefU) > 0)
                            BitLevel.InplaceShiftLeft(r, k - coefV + coefU);
                    }
                    coefU += k;
                }

                k = HowManyIterations(v, n);
                if (k != 0)
                {
                    BitLevel.InplaceShiftLeft(v, k);
                    if (coefV >= coefU)
                    {
                        BitLevel.InplaceShiftLeft(s, k);
                    }
                    else
                    {
                        BitLevel.InplaceShiftRight(r, System.Math.Min(coefU - coefV, k));

                        if (k - (coefU - coefV) > 0)
                            BitLevel.InplaceShiftLeft(s, k - coefU + coefV);
                    }
                    coefV += k;

                }

                if (u.Signum() == v.Signum())
                {
                    if (coefU <= coefV)
                    {
                        Elementary.CompleteInPlaceSubtract(u, v);
                        Elementary.CompleteInPlaceSubtract(r, s);
                    }
                    else
                    {
                        Elementary.CompleteInPlaceSubtract(v, u);
                        Elementary.CompleteInPlaceSubtract(s, r);
                    }
                }
                else
                {
                    if (coefU <= coefV)
                    {
                        Elementary.CompleteInPlaceAdd(u, v);
                        Elementary.CompleteInPlaceAdd(r, s);
                    }
                    else
                    {
                        Elementary.CompleteInPlaceAdd(v, u);
                        Elementary.CompleteInPlaceAdd(s, r);
                    }
                }

                if (v.Signum() == 0 || u.Signum() == 0)
                    throw new ArithmeticException("BigInteger not invertible");
            }

            if (IsPowerOfTwo(v, coefV))
            {
                r = s;
                if (v.Signum() != u.Signum())
                    u = u.Negate();
            }
            if (u.TestBit(n))
            {
                if (r.Signum() < 0)
                    r = r.Negate();
                else
                    r = Modulo.Subtract(r);
            }

            if (r.Signum() < 0)
                r = r.Add(Modulo);

            return r;
        }

        private static BigInteger ModPow2Inverse(BigInteger X, int N)
        {
            // PRE: (x > 0), (x is odd), and (n > 0)
            BigInteger y = new BigInteger(1, new int[1 << N]);
            y._numberLength = 1;
            y._digits[0] = 1;
            y._sign = 1;

            for (int i = 1; i < N; i++)
            {
                if (BitLevel.TestBit(X.Multiply(y), i))
                {
                    // Adding 2^i to y (setting the i-th bit)
                    y._digits[i >> 5] |= (1 << (i & 31));
                }
            }
            return y;
        }

        private static BigInteger MonPro(BigInteger X, BigInteger Y, BigInteger Modulus, int N2)
        {
            // Implements the Montgomery Product of two integers represented by int arrays
            // The arrays are supposed in little endian notation
            int modulusLen = Modulus._numberLength;
            int[] res = new int[(modulusLen << 1) + 1];
            Multiplication.MultiplyArraysPAP(X._digits, System.Math.Min(modulusLen, X._numberLength), Y._digits, System.Math.Min(modulusLen, Y._numberLength), res);
            MonReduction(res, Modulus, N2);

            return FinalSubtraction(res, Modulus);
        }

        private static void MonReduction(int[] Result, BigInteger Modulus, int N2)
        {
            // res + m*modulus_digits
            int[] modulus_digits = Modulus._digits;
            int modulusLen = Modulus._numberLength;
            long outerCarry = 0;

            for (int i = 0; i < modulusLen; i++)
            {
                long innnerCarry = 0;
                int m = (int)Multiplication.UnsignedMultAddAdd(Result[i], N2, 0, 0);
                for (int j = 0; j < modulusLen; j++)
                {
                    innnerCarry = Multiplication.UnsignedMultAddAdd(m, modulus_digits[j], Result[i + j], (int)innnerCarry);
                    Result[i + j] = (int)innnerCarry;
                    innnerCarry = IntUtils.URShift(innnerCarry, 32);
                }

                outerCarry += (Result[i + modulusLen] & 0xFFFFFFFFL) + innnerCarry;
                Result[i + modulusLen] = (int)outerCarry;
                outerCarry = IntUtils.URShift(outerCarry, 32);
            }

            Result[modulusLen << 1] = (int)outerCarry;

            // res / r
            for (int j = 0; j < modulusLen + 1; j++)
                Result[j] = Result[j + modulusLen];
        }

        private static BigInteger Pow2ModPow(BigInteger X, BigInteger Y, int N)
        {
            // PRE: (base > 0), (exponent > 0) and (j > 0)
            BigInteger res = BigInteger.One;
            BigInteger e = Y.Copy();
            BigInteger baseMod2toN = X.Copy();
            BigInteger res2;

            // If 'base' is odd then it's coprime with 2^j and phi(2^j) = 2^(j-1);
            // so we can reduce reduce the exponent (mod 2^(j-1)).
            if (X.TestBit(0))
                InplaceModPow2(e, N - 1);
            
            InplaceModPow2(baseMod2toN, N);

            for (int i = e.BitLength - 1; i >= 0; i--)
            {
                res2 = res.Copy();
                InplaceModPow2(res2, N);
                res = res.Multiply(res2);
                if (BitLevel.TestBit(e, i))
                {
                    res = res.Multiply(baseMod2toN);
                    InplaceModPow2(res, N);
                }
            }
            InplaceModPow2(res, N);

            return res;
        }

        private static BigInteger SlidingWindow(BigInteger X2, BigInteger A2, BigInteger Exponent, BigInteger Modulus, int N2)
        {
            // Implements the Montgomery modular exponentiation based in The sliding windows algorithm and the Mongomery Reduction
            // ar.org.fitc.ref "A. Menezes,P. van Oorschot, S. Vanstone - Handbook of Applied Cryptography"
            BigInteger[] pows = new BigInteger[8];
            BigInteger res = X2;
            int lowexp;
            BigInteger x3;
            int acc3;

            // fill odd low pows of a2
            pows[0] = A2;
            x3 = MonPro(A2, A2, Modulus, N2);

            for (int i = 1; i <= 7; i++)
                pows[i] = MonPro(pows[i - 1], x3, Modulus, N2);

            for (int i = Exponent.BitLength - 1; i >= 0; i--)
            {
                if (BitLevel.TestBit(Exponent, i))
                {
                    lowexp = 1;
                    acc3 = i;

                    for (int j = System.Math.Max(i - 3, 0); j <= i - 1; j++)
                    {
                        if (BitLevel.TestBit(Exponent, j))
                        {
                            if (j < acc3)
                            {
                                acc3 = j;
                                lowexp = (lowexp << (i - j)) ^ 1;
                            }
                            else
                            {
                                lowexp = lowexp ^ (1 << (j - acc3));
                            }
                        }
                    }

                    for (int j = acc3; j <= i; j++)
                        res = MonPro(res, res, Modulus, N2);
                    
                    res = MonPro(pows[(lowexp - 1) >> 1], res, Modulus, N2);
                    i = acc3;
                }
                else
                {
                    res = MonPro(res, res, Modulus, N2);
                }
            }

            return res;
        }

        private static BigInteger SquareAndMultiply(BigInteger X2, BigInteger A2, BigInteger Exponent, BigInteger Modulus, int N2)
        {
            BigInteger res = X2;
            for (int i = Exponent.BitLength - 1; i >= 0; i--)
            {
                res = MonPro(res, res, Modulus, N2);

                if (BitLevel.TestBit(Exponent, i))
                    res = MonPro(res, A2, Modulus, N2);
            }

            return res;
        }
        #endregion
    }
}