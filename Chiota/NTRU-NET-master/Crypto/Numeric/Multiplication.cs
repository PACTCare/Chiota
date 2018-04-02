#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Numeric 
{
    /// <summary>
    /// Static library that provides all multiplication of BigInteger methods
    /// </summary>
    internal sealed class Multiplication
    {
        #region Private Fields
        // Break point in digits (number of int elements) between Karatsuba and Pencil and Paper multiply
        private static readonly int _whenUseKaratsuba = 63;

        // An array with powers of ten that fit in the type int, (0^0,10^1,...,10^9)
        private static readonly int[] tenPows = 
        {
            1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000
        };

        // An array with powers of five that fit in the type int. (5^0,5^1,...,5^13)
        static readonly int[] fivePows = 
        {
            1, 5, 25, 125, 625, 3125, 15625, 78125, 390625, 1953125, 9765625, 48828125, 244140625, 1220703125
        };
        #endregion

        #region Public Fields
        /// <summary>
        /// An array with the first powers of ten in BigInteger version: 10^0,10^1,...,10^31)
        /// </summary>
        internal static readonly BigInteger[] bigTenPows = new BigInteger[32];

        /// <summary>
        /// An array with the first powers of five in {@code BigInteger} version: (5^0,5^1,...,5^31)
        /// </summary>
        internal static readonly BigInteger[] bigFivePows = new BigInteger[32];
        #endregion

        #region Constructors
        static Multiplication()
        {
            int i;
            long fivePow = 1L;

            for (i = 0; i <= 18; i++)
            {
                bigFivePows[i] = BigInteger.ValueOf(fivePow);
                bigTenPows[i] = BigInteger.ValueOf(fivePow << i);
                fivePow *= 5;
            }
            for (; i < bigTenPows.Length; i++)
            {
                bigFivePows[i] = bigFivePows[i - 1].Multiply(bigFivePows[1]);
                bigTenPows[i] = bigTenPows[i - 1].Multiply(BigInteger.Ten);
            }
        }

        private Multiplication()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Performs a multiplication of two BigInteger and hides the algorithm used
        /// </summary>
        /// 
        /// <param name="X">The number to be multiplied</param>
        /// <param name="Y">A positive exponent</param>
        internal static BigInteger Multiply(BigInteger X, BigInteger Y)
        {
            return Karatsuba(X, Y);
        }

        /// <summary>
        /// Multiply a member of array X with array Y
        /// </summary>
        /// 
        /// <param name="X">The number to be multiplied</param>
        /// <param name="XLength">Length of X array to process</param>
        /// <param name="Y">A positive exponent</param>
        /// <param name="YLength">Length of Y array to process</param>
        /// <param name="ResDigits">The result</param>
        internal static void MultiplyArraysPAP(int[] X, int XLength, int[] Y, int YLength, int[] ResDigits)
        {
            if (XLength == 0 || YLength == 0) return;

            if (XLength == 1)
                ResDigits[YLength] = MultiplyByInt(ResDigits, Y, YLength, X[0]);
            else if (YLength == 1)
                ResDigits[XLength] = MultiplyByInt(ResDigits, X, XLength, Y[0]);
            else
                MultPAP(X, Y, ResDigits, XLength, YLength);
        }

        /// <summary>
        /// Multiplies an array of integers by an integer value
        /// </summary>
        /// 
        /// <param name="X">The array of integers</param>
        /// <param name="Size">The number of elements of intArray to be multiplied</param>
        /// <param name="Factor">The multiplier</param>
        /// 
        /// <returns>The top digit of production</returns>
        internal static int MultiplyByInt(int[] X, int Size, int Factor)
        {
            return MultiplyByInt(X, X, Size, Factor);
        }

        /// <summary>
        /// Multiplies a number by a power of five.
        /// <para>This method is used in BigDecimal class.</para>
        /// </summary>
        /// 
        /// <param name="X">The number to be multiplied</param>
        /// <param name="Exponent">A positive int exponent</param>
        /// 
        /// <returns>X * 5 pow Exponent</returns>
        internal static BigInteger MultiplyByFivePow(BigInteger X, int Exponent)
        {
            // PRE: exp >= 0
            if (Exponent < fivePows.Length)
                return MultiplyByPositiveInt(X, fivePows[Exponent]);
            else if (Exponent < bigFivePows.Length)
                return X.Multiply(bigFivePows[Exponent]);
            else
                return X.Multiply(bigFivePows[1].Pow(Exponent));// Large powers of five
        }

        /// <summary>
        /// Multiplies a number by a positive integer.
        /// </summary>
        /// 
        /// <param name="X">An arbitrary BigInteger</param>
        /// <param name="Factor">A positive int number</param>
        /// 
        /// <returns>X * Factor</returns>
        internal static BigInteger MultiplyByPositiveInt(BigInteger X, int Factor)
        {
            int resSign = X._sign;
            if (resSign == 0)
                return BigInteger.Zero;
            
            int aNumberLength = X._numberLength;
            int[] aDigits = X._digits;

            if (aNumberLength == 1)
            {
                long res = UnsignedMultAddAdd(aDigits[0], Factor, 0, 0);
                int resLo = (int)res;
                int resHi = (int)IntUtils.URShift(res, 32);

                return ((resHi == 0) ? 
                    new BigInteger(resSign, resLo) :
                    new BigInteger(resSign, 2, new int[] { resLo, resHi }));
            }
            // Common case
            int resLength = aNumberLength + 1;
            int[] resDigits = new int[resLength];

            resDigits[aNumberLength] = MultiplyByInt(resDigits, aDigits, aNumberLength, Factor);
            BigInteger result = new BigInteger(resSign, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Multiplies a number by a power of ten.
        /// <para>This method is used in BigDecimal class.</para>
        /// </summary>
        /// 
        /// <param name="X">The number to be multiplied</param>
        /// <param name="Exponent">A positive long exponent</param>
        /// 
        /// <returns>X * 10 pow Exponent</returns>
        internal static BigInteger MultiplyByTenPow(BigInteger X, long Exponent)
        {
            // PRE: exp >= 0
            return ((Exponent < tenPows.Length) ? 
                MultiplyByPositiveInt(X, tenPows[(int)Exponent]) : 
                X.Multiply(PowerOf10(Exponent)));
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this ^ Exponent</c>
        /// </summary>
        /// 
        /// <param name="X">The BigInteger</param>
        /// <param name="Exponent">Exponent to which this is raised</param>
        /// 
        /// <returns>Returns <c>this ^ Exponent</c></returns>
        internal static BigInteger Pow(BigInteger X, int Exponent)
        {
            // PRE: exp > 0
            BigInteger res = BigInteger.One;
            BigInteger acc = X;

            for (; Exponent > 1; Exponent >>= 1)
            {
                // if odd, multiply one more time by acc
                if ((Exponent & 1) != 0)
                    res = res.Multiply(acc);
                
                // acc = base^(2^i), a limit where karatsuba performs a faster square than the square algorithm
                if (acc._numberLength == 1)
                    acc = acc.Multiply(acc); 
                else
                    acc = new BigInteger(1, Square(acc._digits, acc._numberLength, new int[acc._numberLength << 1]));
            }
            // exponent == 1, multiply one more time
            res = res.Multiply(acc);

            return res;
        }

        /// <summary>
        /// It calculates a power of ten, which exponent could be out of 32-bit range.
        /// <para>Note that internally this method will be used in the worst case with
        /// an exponent equals to: Integer.Max - Integer.Min.</para>
        /// </summary>
        /// 
        /// <param name="Exponent">The exponent of power of ten, it must be positive</param>
        /// 
        /// <returns>BigInteger with value 10<sup>exp</sup>.</returns>
        internal static BigInteger PowerOf10(long Exponent)
        {
            // PRE: exp >= 0
            int intExp = (int)Exponent;

            // The largest power that fit in 'long' type
            if (Exponent < bigTenPows.Length)
                return bigTenPows[intExp];
            else if (Exponent <= 50) // To calculate: 10^exp
                return BigInteger.Ten.Pow(intExp);
            else if (Exponent <= 1000)// To calculate: 5^exp * 2^exp
                return bigFivePows[1].Pow(intExp).ShiftLeft(intExp);

            // "LARGE POWERS"
            // To check if there is free memory to allocate a BigInteger of the
            // estimated size, measured in bytes: 1 + [exp / log10(2)]
            long byteArraySize = 1 + (long)(Exponent / 2.4082399653118496);

            if (byteArraySize > System.Diagnostics.Process.GetCurrentProcess().PeakVirtualMemorySize64)
                throw new ArithmeticException("power of ten too big");
            if (Exponent <= Int32.MaxValue)
                // To calculate:    5^exp * 2^exp
                return bigFivePows[1].Pow(intExp).ShiftLeft(intExp);

            // "HUGE POWERS"
            // This branch probably won't be executed since the power of ten is too big. To calculate: 5^exp
            BigInteger powerOfFive = bigFivePows[1].Pow(Int32.MaxValue);
            BigInteger res = powerOfFive;
            long longExp = Exponent - Int32.MaxValue;

            intExp = (int)(Exponent % Int32.MaxValue);
            while (longExp > Int32.MaxValue)
            {
                res = res.Multiply(powerOfFive);
                longExp -= Int32.MaxValue;
            }
            res = res.Multiply(bigFivePows[1].Pow(intExp));

            // To calculate: 5^exp << exp
            res = res.ShiftLeft(Int32.MaxValue);
            longExp = Exponent - Int32.MaxValue;
            while (longExp > Int32.MaxValue)
            {
                res = res.ShiftLeft(Int32.MaxValue);
                longExp -= Int32.MaxValue;
            }
            res = res.ShiftLeft(intExp);

            return res;
        }

        /// <summary>
        /// Computes the value unsigned ((uint)a*(uint)b + (uint)c + (uint)d).
        /// <para>This method could improve the readability and performance of the code.</para>
        /// </summary>
        /// 
        /// <param name="A">Operand 1</param>
        /// <param name="B">Operand 2</param>
        /// <param name="C">Operand 3</param>
        /// <param name="D">Operand 4</param>
        /// <returns></returns>
        internal static long UnsignedMultAddAdd(int A, int B, int C, int D)
        {
            return (A & 0xFFFFFFFFL) * (B & 0xFFFFFFFFL) + (C & 0xFFFFFFFFL) + (D & 0xFFFFFFFFL);
        }
        #endregion

        #region Private Methods
        private static BigInteger Karatsuba(BigInteger X, BigInteger Y)
        {
            // Performs the multiplication with the Karatsuba's algorithm
            BigInteger temp;
            if (Y._numberLength > X._numberLength)
            {
                temp = X;
                X = Y;
                Y = temp;
            }

            if (Y._numberLength < _whenUseKaratsuba)
                return MultiplyPAP(X, Y);
            
            //  Karatsuba:  u = u1*B + u0, v = v1*B + v0, u*v = (u1*v1)*B^2 + ((u1-u0)*(v0-v1) + u1*v1 + u0*v0)*B + u0*v0
            int ndiv2 = (int)(X._numberLength & 0xFFFFFFFE) << 4;
            BigInteger upperOp1 = X.ShiftRight(ndiv2);
            BigInteger upperOp2 = Y.ShiftRight(ndiv2);
            BigInteger lowerOp1 = X.Subtract(upperOp1.ShiftLeft(ndiv2));
            BigInteger lowerOp2 = Y.Subtract(upperOp2.ShiftLeft(ndiv2));
            BigInteger upper = Karatsuba(upperOp1, upperOp2);
            BigInteger lower = Karatsuba(lowerOp1, lowerOp2);
            BigInteger middle = Karatsuba(upperOp1.Subtract(lowerOp1), lowerOp2.Subtract(upperOp2));

            middle = middle.Add(upper).Add(lower);
            middle = middle.ShiftLeft(ndiv2);
            upper = upper.ShiftLeft(ndiv2 << 1);

            return upper.Add(middle).Add(lower);
        }

        private static int MultiplyByInt(int[] Result, int[] X, int Size, int Factor)
        {
            // Multiplies an array of integers by an integer value and saves the result in Res
            long carry = 0;
            for (int i = 0; i < Size; i++)
            {
                carry = UnsignedMultAddAdd(X[i], Factor, (int)carry, 0);
                Result[i] = (int)carry;
                carry = IntUtils.URShift(carry, 32);
            }

            return (int)carry;
        }

        private static BigInteger MultiplyPAP(BigInteger X, BigInteger Y)
        {
            // Multiplies two BigIntegers. Implements traditional scholar algorithm described by Knuth.
            // PRE: a >= b
            int aLen = X._numberLength;
            int bLen = Y._numberLength;
            int resLength = aLen + bLen;
            int resSign = (X._sign != Y._sign) ? -1 : 1;
            // A special case when both numbers don't exceed int
            if (resLength == 2)
            {
                long val = UnsignedMultAddAdd(X._digits[0], Y._digits[0], 0, 0);
                int valueLo = (int)val;
                int valueHi = (int)IntUtils.URShift(val, 32);

                return ((valueHi == 0) ? 
                    new BigInteger(resSign, valueLo) : 
                    new BigInteger(resSign, 2, new int[] { valueLo, valueHi }));
            }
            int[] aDigits = X._digits;
            int[] bDigits = Y._digits;
            int[] resDigits = new int[resLength];
            // Common case
            MultiplyArraysPAP(aDigits, aLen, bDigits, bLen, resDigits);
            BigInteger result = new BigInteger(resSign, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }
        
        private static void MultPAP(int[] X, int[] Y, int[] T, int ALen, int BLen)
        {
            if (X == Y && ALen == BLen)
            {
                Square(X, ALen, T);
                return;
            }

            for (int i = 0; i < ALen; i++)
            {
                long carry = 0;
                int aI = X[i];

                for (int j = 0; j < BLen; j++)
                {
                    carry = UnsignedMultAddAdd(aI, Y[j], T[i + j], (int)carry);
                    T[i + j] = (int)carry;
                    carry = IntUtils.URShift(carry, 32);
                }
                T[i + BLen] = (int)carry;
            }
        }

        private static int[] Square(int[] X, int XLen, int[] Result)
        {
            long carry;

            for (int i = 0; i < XLen; i++)
            {
                carry = 0;
                for (int j = i + 1; j < XLen; j++)
                {
                    carry = UnsignedMultAddAdd(X[i], X[j], Result[i + j], (int)carry);
                    Result[i + j] = (int)carry;
                    carry = IntUtils.URShift(carry, 32);
                }
                Result[i + XLen] = (int)carry;
            }

            BitLevel.ShiftLeftOneBit(Result, Result, XLen << 1);

            carry = 0;
            for (int i = 0, index = 0; i < XLen; i++, index++)
            {
                carry = UnsignedMultAddAdd(X[i], X[i], Result[index], (int)carry);
                Result[index] = (int)carry;
                carry = IntUtils.URShift(carry, 32);
                index++;
                carry += Result[index] & 0xFFFFFFFFL;
                Result[index] = (int)carry;
                carry = IntUtils.URShift(carry, 32);
            }
            return Result;
        }
        #endregion
    }
}