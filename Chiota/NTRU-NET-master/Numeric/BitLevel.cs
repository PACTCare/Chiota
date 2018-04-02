#region Directives
using System;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// Static library that provides all the bit level operations for BigInteger. 
    /// 
    /// <description>The operations are:</description>
    /// <list type="number">
    /// <item><description>Left Shifting</description></item>
    /// <item><description>Right Shifting</description></item>
    /// <item><description>Bit Clearing</description></item>
    /// <item><description>Bit Setting</description></item>
    /// <item><description>Bit Counting</description></item>
    /// <item><description>Bit Testing</description></item>
    /// <item><description>Getting of the lowest bit set</description></item>
    /// </list>
    /// 
    /// <para>All operations are provided in immutable way, and some in both mutable and immutable.</para>
    /// </summary>
    internal sealed class BitLevel
    {
        #region Constructor
        private BitLevel()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Returns the number of bits in the binary representation of this which differ from the sign bit. 
        /// <para>Use BitLength(0) if you want to know the length of the binary value in bits.
        /// If this is positive the result is equivalent to the number of bits set in the binary representation of this.
        /// If this is negative the result is equivalent to the number of bits set in the binary representation of -this - 1.</para>
        /// </summary>
        internal static int BitCount(BigInteger Value)
        {
            int bCount = 0;

            if (Value._sign == 0)
                return 0;

            int i = Value.FirstNonzeroDigit; ;
            if (Value._sign > 0)
            {
                for (; i < Value._numberLength; i++)
                    bCount += IntUtils.BitCount(Value._digits[i]);
            }
            else
            {
                // this digit absorbs the carry
                bCount += IntUtils.BitCount(-Value._digits[i]);

                for (i++; i < Value._numberLength; i++)
                    bCount += IntUtils.BitCount(~Value._digits[i]);

                // We take the complement sum:
                bCount = (Value._numberLength << 5) - bCount;
            }
            return bCount;
        }

        /// <summary>
        /// Returns the length of the value's two's complement representation without 
        /// leading zeros for positive numbers / without leading ones for negative values.
        /// <para>The two's complement representation of this will be at least BitLength() + 1 bits long.
        /// The value will fit into an int if <c>bitLength() &lt; 32</c> or into a long if <c>bitLength() &lt; 64</c>.</para>
        /// </summary>
        internal static int BitLength(BigInteger Value)
        {
            if (Value._sign == 0)
                return 0;

            int bLength = (Value._numberLength << 5);
            int highDigit = Value._digits[Value._numberLength - 1];

            if (Value._sign < 0)
            {
                int i = Value.FirstNonzeroDigit;
                // We reduce the problem to the positive case.
                if (i == Value._numberLength - 1)
                    highDigit--;
            }
            // Subtracting all sign bits
            bLength -= IntUtils.NumberOfLeadingZeros(highDigit);
            return bLength;
        }

        /// <summary>
        /// Returns a new BigInteger which has the same binary representation 
        /// as this but with the bit at position N flipped. 
        /// <para>The result is equivalent to this ^ 2^N.</para>
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        /// <param name="N">Position where the bit in this has to be flipped</param>
        /// 
        /// <returns>Returns <c>this ^ 2^N</c></returns>
        /// 
        /// <exception cref="ArithmeticException">Thrown if a negative bit address is used</exception>
        internal static BigInteger FlipBit(BigInteger Value, int N)
        {
            int resSign = (Value._sign == 0) ? 1 : Value._sign;
            int intCount = N >> 5;
            int bitN = N & 31;
            int resLength = System.Math.Max(intCount + 1, Value._numberLength) + 1;
            int[] resDigits = new int[resLength];
            int i;

            int bitNumber = 1 << bitN;
            Array.Copy(Value._digits, 0, resDigits, 0, Value._numberLength);

            if (Value._sign < 0)
            {
                if (intCount >= Value._numberLength)
                {
                    resDigits[intCount] = bitNumber;
                }
                else
                {
                    //val.sign<0 y intCount < val.numberLength
                    int firstNonZeroDigit = Value.FirstNonzeroDigit;
                    if (intCount > firstNonZeroDigit)
                    {
                        resDigits[intCount] ^= bitNumber;
                    }
                    else if (intCount < firstNonZeroDigit)
                    {
                        resDigits[intCount] = -bitNumber;
                        for (i = intCount + 1; i < firstNonZeroDigit; i++)
                            resDigits[i] = -1;

                        resDigits[i] = resDigits[i]--;
                    }
                    else
                    {
                        i = intCount;
                        resDigits[i] = -((-resDigits[intCount]) ^ bitNumber);
                        if (resDigits[i] == 0)
                        {
                            for (i++; resDigits[i] == -1; i++)
                                resDigits[i] = 0;

                            resDigits[i]++;
                        }
                    }
                }
            }
            else
            {   //case where val is positive
                resDigits[intCount] ^= bitNumber;
            }

            BigInteger result = new BigInteger(resSign, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Performs val &lt;= count, val should have enough place (and one digit more)
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        /// <param name="N">Shift distance</param>
        internal static void InplaceShiftLeft(BigInteger Value, int N)
        {
            int intCount = N >> 5; // count of integers
            Value._numberLength += intCount + (IntUtils.NumberOfLeadingZeros(Value._digits[Value._numberLength - 1]) - (N & 31) >= 0 ? 0 : 1);
            ShiftLeft(Value._digits, Value._digits, intCount, N & 31);
            Value.CutOffLeadingZeroes();
            Value.UnCache();
        }

        /// <summary>
        /// Performs Value >>= count where Value is a positive number.
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        /// <param name="N">Shift distance</param>
        internal static void InplaceShiftRight(BigInteger Value, int N)
        {
            int sign = Value.Signum();

            if (N == 0 || Value.Signum() == 0)
                return;

            int intCount = N >> 5; // count of integers
            Value._numberLength -= intCount;
            if (!ShiftRight(Value._digits, Value._numberLength, Value._digits, intCount, N & 31) && sign < 0)
            {
                // remainder not zero: add one to the result
                int i;
                for (i = 0; (i < Value._numberLength) && (Value._digits[i] == -1); i++)
                    Value._digits[i] = 0;

                if (i == Value._numberLength)
                    Value._numberLength++;

                Value._digits[i]++;
            }
            Value.CutOffLeadingZeroes();
            Value.UnCache();
        }

        /// <summary>
        /// Check if there are 1s in the lowest bits of this BigInteger
        /// </summary>
        internal static bool NonZeroDroppedBits(int NumberOfBits, int[] Digits)
        {
            int intCount = NumberOfBits >> 5;
            int bitCount = NumberOfBits & 31;
            int i;

            for (i = 0; (i < intCount) && (Digits[i] == 0); i++)
            {
                ;
            }
            return ((i != intCount) || (Digits[i] << (32 - bitCount) != 0));
        }

        /// <summary>
        /// Returns a new BigInteger whose value is this &lt;&lt; N.
        /// <para>The result is equivalent to <c>this * 2^n</c> if n >= 0.
        /// The shift distance may be negative which means that this is shifted right.
        /// The result then corresponds to <c>Floor(this / 2^(-n))</c>.</para>
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        /// <param name="N">Shift distance</param>
        /// 
        /// <returns>Returns <c>this &lt;&lt; N</c> if n >= 0, <c>this >> (-N)</c> otherwise</returns>
        internal static BigInteger ShiftLeft(BigInteger Value, int N)
        {
            int intCount = N >> 5;
            N &= 31; // %= 32
            int resLength = Value._numberLength + intCount + ((N == 0) ? 0 : 1);
            int[] resDigits = new int[resLength];

            ShiftLeft(resDigits, Value._digits, intCount, N);
            BigInteger result = new BigInteger(Value._sign, resLength, resDigits);
            result.CutOffLeadingZeroes();
            return result;
        }

        /// <summary>
        /// Abstractly shifts left an array of integers in little endian (i.e. shift it right).
        /// Total shift distance in bits is intCount * 32 + count
        /// </summary>
        /// 
        /// <param name="Result">The result</param>
        /// <param name="Value">The source BigIntger</param>
        /// <param name="IntCount">The number integers</param>
        /// <param name="N">The number of bits to shift</param>
        internal static void ShiftLeft(int[] Result, int[] Value, int IntCount, int N)
        {
            if (N == 0)
            {
                Array.Copy(Value, 0, Result, IntCount, Result.Length - IntCount);
            }
            else
            {
                int rightShiftCount = 32 - N;

                Result[Result.Length - 1] = 0;
                for (int i = Result.Length - 1; i > IntCount; i--)
                {
                    Result[i] |= IntUtils.URShift(Value[i - IntCount - 1], rightShiftCount);
                    Result[i - 1] = Value[i - IntCount - 1] << N;
                }
            }

            for (int i = 0; i < IntCount; i++)
            {
                Result[i] = 0;
            }
        }

        /// <summary>
        /// Shifts the source digits left one bit, creating a value whose magnitude is doubled.
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        internal static BigInteger ShiftLeftOneBit(BigInteger Value)
        {
            int srcLen = Value._numberLength;
            int resLen = srcLen + 1;
            int[] resDigits = new int[resLen];
            ShiftLeftOneBit(resDigits, Value._digits, srcLen);
            BigInteger result = new BigInteger(Value._sign, resLen, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Shifts the source digits left one bit, creating a value whose magnitude is doubled.
        /// </summary>
        /// 
        /// <param name="Result">The result</param>
        /// <param name="Value">The source BigIntger</param>
        /// <param name="ValueLen">The value length</param>
        internal static void ShiftLeftOneBit(int[] Result, int[] Value, int ValueLen)
        {
            int carry = 0;
            for (int i = 0; i < ValueLen; i++)
            {
                int val = Value[i];
                Result[i] = (val << 1) | carry;
                carry = IntUtils.URShift(val, 31);
            }
            if (carry != 0)
            {
                Result[ValueLen] = carry;
            }
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this >> N</c>
        /// <para>For negative arguments, the result is also negative. 
        /// The shift distance may be negative which means that this is shifted left.
        /// </para>
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        /// <param name="N">Shift distance</param>
        /// 
        /// <returns>this >> N, if N >= 0; this &lt;&lt; (-n) otherwise</returns>
        internal static BigInteger ShiftRight(BigInteger Value, int N)
        {
            int intCount = N >> 5; // count of integers
            N &= 31; // count of remaining bits

            if (intCount >= Value._numberLength)
                return ((Value._sign < 0) ? BigInteger.MinusOne : BigInteger.Zero);

            int i;
            int resLength = Value._numberLength - intCount;
            int[] resDigits = new int[resLength + 1];

            ShiftRight(resDigits, resLength, Value._digits, intCount, N);
            if (Value._sign < 0)
            {
                // Checking if the dropped bits are zeros (the remainder equals to 0)
                for (i = 0; (i < intCount) && (Value._digits[i] == 0); i++)
                {
                    ;
                }
                // If the remainder is not zero, add 1 to the result
                if ((i < intCount)
                        || ((N > 0) && ((Value._digits[i] << (32 - N)) != 0)))
                {
                    for (i = 0; (i < resLength) && (resDigits[i] == -1); i++)
                        resDigits[i] = 0;

                    if (i == resLength)
                        resLength++;

                    resDigits[i]++;
                }
            }
            BigInteger result = new BigInteger(Value._sign, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this >> N</c>
        /// <para>For negative arguments, the result is also negative. 
        /// The shift distance may be negative which means that this is shifted left.
        /// </para>
        /// </summary>
        /// 
        /// <param name="Result">The result</param>
        /// <param name="ResultLen">The result length</param>
        /// <param name="Value">The source BigIntger</param>
        /// <param name="IntCount">The number integers</param>
        /// <param name="N">Shift distance</param>
        /// 
        /// <returns>this >> N, if N >= 0; this &lt;&lt; (-n) otherwise</returns>
        internal static bool ShiftRight(int[] Result, int ResultLen, int[] Value, int IntCount, int N)
        {
            int i;
            bool allZero = true;
            for (i = 0; i < IntCount; i++)
                allZero &= Value[i] == 0;
            if (N == 0)
            {
                Array.Copy(Value, IntCount, Result, 0, ResultLen);
                i = ResultLen;
            }
            else
            {
                int leftShiftCount = 32 - N;

                allZero &= (Value[i] << leftShiftCount) == 0;
                for (i = 0; i < ResultLen - 1; i++)
                {
                    Result[i] = IntUtils.URShift(Value[i + IntCount], N) |
                                (Value[i + IntCount + 1] << leftShiftCount);
                }
                Result[i] = IntUtils.URShift(Value[i + IntCount], N);
                i++;
            }

            return allZero;
        }

        /// <summary>
        /// Tests whether the bit at position N in this is set.
        /// <para>The result is equivalent to <c>this &amp; (2^n) != 0</c>.</para>
        /// </summary>
        /// 
        /// <param name="Value">The source BigIntger</param>
        /// <param name="N">Position where the bit in this has to be inspected.</param>
        /// 
        /// <returns>Returns this &amp; (2^n) != 0</returns>
        internal static bool TestBit(BigInteger Value, int N)
        {
            // PRE: 0 <= n < val.bitLength()
            return ((Value._digits[N >> 5] & (1 << (N & 31))) != 0);
        }
        #endregion
    }
}