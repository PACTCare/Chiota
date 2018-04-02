#region Directives
using System;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// Static library that provides the basic arithmetic mutable operations for BigInteger.
    /// 
    /// <description>The operations provided are:</description>
    /// <list type="bullet">
    /// <item><description>Addition</description></item>
    /// <item><description>Subtraction</description></item>
    /// <item><description>Comparison</description>/></item>
    /// </list>
    /// 
    /// <para>In addition to this, some Inplace (mutable) methods are provided.</para>
    /// </summary>
    internal sealed class Elementary
    {
        #region Constructor
        private Elementary()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// See BigInteger#add(BigInteger)
        /// </summary>
        internal static BigInteger Add(BigInteger A, BigInteger B)
        {
            int[] resDigits;
            int resSign;
            int op1Sign = A._sign;
            int op2Sign = B._sign;

            if (op1Sign == 0)
                return B;
            if (op2Sign == 0)
                return A;

            int op1Len = A._numberLength;
            int op2Len = B._numberLength;

            if (op1Len + op2Len == 2)
            {
                long a = (A._digits[0] & 0xFFFFFFFFL);
                long b = (B._digits[0] & 0xFFFFFFFFL);
                long res;
                int valueLo;
                int valueHi;

                if (op1Sign == op2Sign)
                {
                    res = a + b;
                    valueLo = (int)res;
                    valueHi = (int)IntUtils.URShift(res, 32);

                    return ((valueHi == 0)
                                ? new BigInteger(op1Sign, valueLo)
                                : new BigInteger(op1Sign, 2, new int[] { valueLo, valueHi }));
                }

                return BigInteger.ValueOf((op1Sign < 0) ? (b - a) : (a - b));
            }
            else if (op1Sign == op2Sign)
            {
                resSign = op1Sign;
                // an augend should not be shorter than addend
                resDigits = (op1Len >= op2Len) ?
                    Add(A._digits, op1Len, B._digits, op2Len) :
                    Add(B._digits, op2Len, A._digits, op1Len);
            }
            else
            {
                // signs are different
                int cmp = ((op1Len != op2Len) ?
                    ((op1Len > op2Len) ? 1 : -1) :
                    CompareArrays(A._digits, B._digits, op1Len));

                if (cmp == BigInteger.EQUALS)
                    return BigInteger.Zero;

                // a minuend should not be shorter than subtrahend
                if (cmp == BigInteger.GREATER)
                {
                    resSign = op1Sign;
                    resDigits = Subtract(A._digits, op1Len, B._digits, op2Len);
                }
                else
                {
                    resSign = op2Sign;
                    resDigits = Subtract(B._digits, op2Len, A._digits, op1Len);
                }
            }
            BigInteger result = new BigInteger(resSign, resDigits.Length, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        /// <summary>
        /// Compares two arrays. All elements are treated as unsigned integers. 
        /// <para>The magnitude is the bit chain of elements in big-endian order.</para>
        /// </summary>
        /// 
        /// <param name="A">The first array</param>
        /// <param name="B">The second array</param>
        /// <param name="Size">Size the size of arrays</param>
        /// 
        /// <returns>Returns 1 if A > B, -1 if A &lt; B, 0 if A == B</returns>
        internal static int CompareArrays(int[] A, int[] B, int Size)
        {
            int i;
            for (i = Size - 1; (i >= 0) && (A[i] == B[i]); i--)
            {
                ;
            }

            return ((i < 0) ?
                BigInteger.EQUALS :
                (A[i] & 0xFFFFFFFFL) < (B[i] & 0xFFFFFFFFL) ? BigInteger.LESS : BigInteger.GREATER);
        }

        /// <summary>
        /// Same as InplaceAdd(BigInteger, BigInteger), but without the restriction of non-positive values
        /// </summary>
        /// 
        /// <param name="A">The operand</param>
        /// <param name="B">The addend</param>
        internal static void CompleteInPlaceAdd(BigInteger A, BigInteger B)
        {
            if (A._sign == 0)
            {
                Array.Copy(B._digits, 0, A._digits, 0, B._numberLength);
            }
            else if (B._sign == 0)
            {
                return;
            }
            else if (A._sign == B._sign)
            {
                Add(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);
            }
            else
            {
                int sign = UnsignedArraysCompare(A._digits, B._digits, A._numberLength, B._numberLength);
                if (sign > 0)
                {
                    Subtract(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);
                }
                else
                {
                    InverseSubtract(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);
                    A._sign = -A._sign;
                }
            }
            A._numberLength = System.Math.Max(A._numberLength, B._numberLength) + 1;
            A.CutOffLeadingZeroes();
            A.UnCache();
        }

        /// <summary>
        /// Same as InplaceSubtract(BigInteger, BigInteger), but without the restriction of non-positive values
        /// <para>Op1 should have enough space to save the result</para>
        /// </summary>
        /// 
        /// <param name="A">The input minuend, and the output result</param>
        /// <param name="B">The subtrahend</param>
        internal static void CompleteInPlaceSubtract(BigInteger A, BigInteger B)
        {
            int resultSign = A.CompareTo(B);

            if (A._sign == 0)
            {
                Array.Copy(B._digits, 0, A._digits, 0, B._numberLength);
                A._sign = -B._sign;
            }
            else if (A._sign != B._sign)
            {
                Add(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);
                A._sign = resultSign;
            }
            else
            {
                int sign = UnsignedArraysCompare(A._digits,
                        B._digits, A._numberLength, B._numberLength);
                if (sign > 0)
                {
                    Subtract(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);	// op1 = op1 - op2
                    // op1.sign remains equal
                }
                else
                {
                    InverseSubtract(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);	// op1 = op2 - op1
                    A._sign = -A._sign;
                }
            }
            A._numberLength = System.Math.Max(A._numberLength, B._numberLength) + 1;
            A.CutOffLeadingZeroes();
            A.UnCache();
        }

        /// <summary>
        /// Performs Op1 += Op2.
        /// <para>Op1 must have enough place to store the result (i.e. Op1.BitLength() >= Op2.BitLength()). 
        /// Both should be positive (i.e. Op1 >= Op2).</para>
        /// </summary>
        /// 
        /// <param name="A">The input minuend, and the output result</param>
        /// <param name="B">The addend</param>
        internal static void InplaceAdd(BigInteger A, BigInteger B)
        {
            // op1 >= op2 > 0
            Add(A._digits, A._digits, A._numberLength, B._digits, B._numberLength);
            A._numberLength = System.Math.Min(System.Math.Max(A._numberLength, B._numberLength) + 1, A._digits.Length);
            A.CutOffLeadingZeroes();
            A.UnCache();
        }

        /// <summary>
        /// Adds an integer value to the array of integers remembering carry
        /// </summary>
        /// 
        /// <param name="A">The input minuend</param>
        /// <param name="ASize">The minuend size</param>
        /// <param name="Addend">The addend</param>
        /// 
        /// <returns>A possible generated carry (0 or 1)</returns>
        internal static int InplaceAdd(int[] A, int ASize, int Addend)
        {
            long carry = Addend & 0xFFFFFFFFL;

            for (int i = 0; (carry != 0) && (i < ASize); i++)
            {
                carry += A[i] & 0xFFFFFFFFL;
                A[i] = (int)carry;
                carry >>= 32;
            }
            return (int)carry;
        }

        /// <summary>
        /// Performs: Op1 += Addend. 
        /// <para>The number must have a place to hold a possible carry.</para>
        /// </summary>
        /// 
        /// <param name="A">The operand</param>
        /// <param name="Addend">The addend</param>
        internal static void InplaceAdd(BigInteger A, int Addend)
        {
            int carry = InplaceAdd(A._digits, A._numberLength, Addend);
            if (carry == 1)
            {
                A._digits[A._numberLength] = 1;
                A._numberLength++;
            }

            A.UnCache();
        }

        /// <summary>
        /// Performs Op1 -= Op2. 
        /// <para>Op1 must have enough place to store the result (i.e. Op1.BitLength() >= Op2.BitLength()).
        /// Both should be positive (what implies that Op1 >= Op2).</para>
        /// </summary>
        /// 
        /// <param name="A">The input minuend, and the output result</param>
        /// <param name="B">The subtrahend</param>
        internal static void InplaceSubtract(BigInteger A, BigInteger B)
        {
            // PRE: op1 >= op2 > 0
            Subtract(A._digits, A._digits, A._numberLength, B._digits,
                    B._numberLength);
            A.CutOffLeadingZeroes();
            A.UnCache();
        }

        /// <summary>
        /// See BigInteger#subtract(BigInteger)
        /// </summary>
        internal static BigInteger Subtract(BigInteger A, BigInteger B)
        {
            int resSign;
            int[] resDigits;
            int op1Sign = A._sign;
            int op2Sign = B._sign;

            if (op2Sign == 0)
                return A;
            if (op1Sign == 0)
                return B.Negate();

            int op1Len = A._numberLength;
            int op2Len = B._numberLength;
            if (op1Len + op2Len == 2)
            {
                long a = (A._digits[0] & 0xFFFFFFFFL);
                long b = (B._digits[0] & 0xFFFFFFFFL);

                if (op1Sign < 0)
                    a = -a;
                if (op2Sign < 0)
                    b = -b;

                return BigInteger.ValueOf(a - b);
            }
            int cmp = ((op1Len != op2Len) ?
                ((op1Len > op2Len) ? 1 : -1) :
                Elementary.CompareArrays(A._digits, B._digits, op1Len));

            if (cmp == BigInteger.LESS)
            {
                resSign = -op2Sign;
                resDigits = (op1Sign == op2Sign) ?
                    Subtract(B._digits, op2Len, A._digits, op1Len) :
                    Add(B._digits, op2Len, A._digits, op1Len);
            }
            else
            {
                resSign = op1Sign;
                if (op1Sign == op2Sign)
                {
                    if (cmp == BigInteger.EQUALS)
                        return BigInteger.Zero;

                    resDigits = Subtract(A._digits, op1Len, B._digits, op2Len);
                }
                else
                {
                    resDigits = Add(A._digits, op1Len, B._digits, op2Len);
                }
            }
            BigInteger res = new BigInteger(resSign, resDigits.Length, resDigits);
            res.CutOffLeadingZeroes();

            return res;
        }
        #endregion

        #region Private Methods
        private static int[] Add(int[] A, int ASize, int[] B, int BSize)
        {
            // Adds the value represented by B to the value represented by A. 
            // It is assumed the magnitude of A is not less than the magnitude of B.
            // PRE: a[] >= b[]
            int[] res = new int[ASize + 1];
            Add(res, A, ASize, B, BSize);

            return res;
        }

        private static int[] Subtract(int[] A, int ASize, int[] B, int BSize)
        {
            // Subtracts the value represented by B from the value represented by A. 
            // It is assumed the magnitude of A is not less than the magnitude of B.
            // a[] >= b[]
            int[] res = new int[ASize];
            Subtract(res, A, ASize, B, BSize);

            return res;
        }

        private static void Add(int[] Res, int[] A, int ASize, int[] B, int BSize)
        {
            // PRE: a.Length < max(aSize, bSize)

            int i;
            long carry = (A[0] & 0xFFFFFFFFL) + (B[0] & 0xFFFFFFFFL);

            Res[0] = (int)carry;
            carry = (long)(ulong)carry >> 32;

            if (ASize >= BSize)
            {
                for (i = 1; i < BSize; i++)
                {
                    carry += (A[i] & 0xFFFFFFFFL) + (B[i] & 0xFFFFFFFFL);
                    Res[i] = (int)carry;
                    carry = (long)(ulong)carry >> 32;
                }
                for (; i < ASize; i++)
                {
                    carry += A[i] & 0xFFFFFFFFL;
                    Res[i] = (int)carry;
                    carry >>= 32;
                }
            }
            else
            {
                for (i = 1; i < ASize; i++)
                {
                    carry += (A[i] & 0xFFFFFFFFL) + (B[i] & 0xFFFFFFFFL);
                    Res[i] = (int)carry;
                    carry = (long)(ulong)carry >> 32;
                }
                for (; i < BSize; i++)
                {
                    carry += B[i] & 0xFFFFFFFFL;
                    Res[i] = (int)carry;
                    carry = (long)(ulong)carry >> 32;
                }
            }

            if (carry != 0)
                Res[i] = (int)carry;
        }

        private static void InverseSubtract(int[] Result, int[] A, int ASize, int[] B, int BSize)
        {
            // Performs Res = B - A
            int i;
            long borrow = 0;

            if (ASize < BSize)
            {
                for (i = 0; i < ASize; i++)
                {
                    borrow += (B[i] & 0xFFFFFFFFL) - (A[i] & 0xFFFFFFFFL);
                    Result[i] = (int)borrow;
                    borrow >>= 32; // -1 or 0
                }
                for (; i < BSize; i++)
                {
                    borrow += B[i] & 0xFFFFFFFFL;
                    Result[i] = (int)borrow;
                    borrow >>= 32; // -1 or 0
                }
            }
            else
            {
                for (i = 0; i < BSize; i++)
                {
                    borrow += (B[i] & 0xFFFFFFFFL) - (A[i] & 0xFFFFFFFFL);
                    Result[i] = (int)borrow;
                    borrow >>= 32; // -1 or 0
                }
                for (; i < ASize; i++)
                {
                    borrow -= A[i] & 0xFFFFFFFFL;
                    Result[i] = (int)borrow;
                    borrow >>= 32; // -1 or 0
                }
            }

        }

        private static void Subtract(int[] Res, int[] A, int ASize, int[] B, int BSize)
        {
            // Performs res = a - b. It is assumed the magnitude of a is not less than the magnitude of b
            // PRE: a[] >= b[]
            int i;
            long borrow = 0;

            for (i = 0; i < BSize; i++)
            {
                borrow += (A[i] & 0xFFFFFFFFL) - (B[i] & 0xFFFFFFFFL);
                Res[i] = (int)borrow;
                borrow >>= 32; // -1 or 0
            }
            for (; i < ASize; i++)
            {
                borrow += A[i] & 0xFFFFFFFFL;
                Res[i] = (int)borrow;
                borrow >>= 32; // -1 or 0
            }
        }

        private static int UnsignedArraysCompare(int[] A, int[] B, int ASize, int BSize)
        {
            // Compares two arrays, representing unsigned integer in little-endian order.
            // Returns +1,0,-1 if A is - respective - greater, equal or lesser then B 
            if (ASize > BSize)
                return 1;
            else if (ASize < BSize)
                return -1;

            else
            {
                int i;
                for (i = ASize - 1; i >= 0 && A[i] == B[i]; i--)
                {
                    ;
                }

                return i < 0 ?
                    BigInteger.EQUALS :
                    ((A[i] & 0xFFFFFFFFL) < (B[i] & 0xFFFFFFFFL) ?
                    BigInteger.LESS :
                    BigInteger.GREATER);
            }
        }
        #endregion
    }
}