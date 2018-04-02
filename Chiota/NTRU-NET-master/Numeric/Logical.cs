#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric
{
    /// <summary>
    /// This class implements some logical operations over BigInteger.
    /// 
    /// <description>The operations provided are:</description>
    /// <list type="bullet">
    /// <item><description>Not</description></item>
    /// <item><description>And</description></item>
    /// <item><description>AndNot</description>/></item>
    /// <item><description>Or</description>/></item>
    /// <item><description>Xor</description>/></item>
    /// </list>
    /// </summary>
    internal sealed class Logical
    {
        #region Constructor
        private Logical() { }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Returns a new BigInteger whose value is ~Value.
        /// <para>The result of this operation is <c>-this-1</c>.</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be Not'ed</param>
        /// 
        /// <returns>Returns <c>~Value</c></returns>
        internal static BigInteger Not(BigInteger Value)
        {
            if (Value._sign == 0)
                return BigInteger.MinusOne;
            if (Value.Equals(BigInteger.MinusOne))
                return BigInteger.Zero;

            int[] resDigits = new int[Value._numberLength + 1];
            int i;

            if (Value._sign > 0)
            {
                // ~val = -val + 1
                if (Value._digits[Value._numberLength - 1] != -1)
                {
                    for (i = 0; Value._digits[i] == -1; i++)
                    {
                        ;
                    }
                }
                else
                {
                    for (i = 0; (i < Value._numberLength) && (Value._digits[i] == -1); i++)
                    {
                        ;
                    }
                    if (i == Value._numberLength)
                    {
                        resDigits[i] = 1;
                        return new BigInteger(-Value._sign, i + 1, resDigits);
                    }
                }
                // Here a carry 1 was generated
            }
            else
            {
                // ~val = -val - 1
                for (i = 0; Value._digits[i] == 0; i++)
                    resDigits[i] = -1;
            }

            // Now, the carry/borrow can be absorbed
            resDigits[i] = Value._digits[i] + Value._sign;
            // Copying the remaining unchanged digit
            for (i++; i < Value._numberLength; i++)
                resDigits[i] = Value._digits[i];

            return new BigInteger(-Value._sign, i, resDigits);
        }

        /// <summary>
        /// Computes the bit per bit operator between this number and the given one.
        /// </summary>
        /// 
        /// <param name="Value">The value to be And'ed with X</param>
        /// <param name="X">The second value</param>
        /// 
        /// <returns>
        /// Returns a new BigInteger whose value is <c>Value &amp; X</c>.
        /// </returns>
        internal static BigInteger And(BigInteger Value, BigInteger X)
        {
            if (X._sign == 0 || Value._sign == 0)
                return BigInteger.Zero;
            if (X.Equals(BigInteger.MinusOne))
                return Value;
            if (Value.Equals(BigInteger.MinusOne))
                return X;

            if (Value._sign > 0)
            {
                if (X._sign > 0)
                    return AndPositive(Value, X);
                else
                    return AndDiffSigns(Value, X);
            }
            else
            {
                if (X._sign > 0)
                    return AndDiffSigns(X, Value);
                else if (Value._numberLength > X._numberLength)
                    return AndNegative(Value, X);
                else
                    return AndNegative(X, Value);
            }
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this &amp; ~Value</c>.
        /// <para>Evaluating <c>x.AndNot(Value)</c> returns the same result as <c>x.And(Value.Not())</c>.</para>
        /// </summary>
        /// 
        /// <param name="Value">Value to be Not'ed and then And'ed</param>
        /// <param name="X">The second value</param>
        /// 
        /// <returns><c>Value &amp; ~X</c></returns>
        internal static BigInteger AndNot(BigInteger Value, BigInteger X)
        {
            if (X._sign == 0)
                return Value;
            if (Value._sign == 0)
                return BigInteger.Zero;
            if (Value.Equals(BigInteger.MinusOne))
                return X.Not();
            if (X.Equals(BigInteger.MinusOne))
                return BigInteger.Zero;

            //if val == that, return 0

            if (Value._sign > 0)
            {
                if (X._sign > 0)
                    return AndNotPositive(Value, X);
                else
                    return AndNotPositiveNegative(Value, X);
            }
            else
            {
                if (X._sign > 0)
                    return AndNotNegativePositive(Value, X);
                else
                    return AndNotNegative(Value, X);
            }
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this | Value</c>.
        /// </summary>
        /// 
        /// <param name="Value">Value to be Or'ed</param>
        /// <param name="X">The second value</param>
        /// 
        /// <returns>Returns <c>this | Value</c></returns>
        internal static BigInteger Or(BigInteger Value, BigInteger X)
        {
            if (X.Equals(BigInteger.MinusOne) || Value.Equals(BigInteger.MinusOne))
                return BigInteger.MinusOne;
            if (X._sign == 0)
                return Value;
            if (Value._sign == 0)
                return X;

            if (Value._sign > 0)
            {
                if (X._sign > 0)
                {
                    if (Value._numberLength > X._numberLength)
                        return OrPositive(Value, X);
                    else
                        return OrPositive(X, Value);
                }
                else
                {
                    return OrDiffSigns(Value, X);
                }
            }
            else
            {
                if (X._sign > 0)
                    return OrDiffSigns(X, Value);
                else if (X.FirstNonzeroDigit > Value.FirstNonzeroDigit)
                    return OrNegative(X, Value);
                else
                    return OrNegative(Value, X);
            }
        }

        /// <summary>
        /// Returns a new BigInteger whose value is <c>this ^ Value</c>
        /// </summary>
        /// 
        /// <param name="Value">Value to be Xor'ed </param>
        /// <param name="X">The second value</param>
        /// 
        /// <returns>Returns <c>this ^ Value</c></returns>
        internal static BigInteger Xor(BigInteger Value, BigInteger X)
        {
            if (X._sign == 0)
                return Value;
            if (Value._sign == 0)
                return X;
            if (X.Equals(BigInteger.MinusOne))
                return Value.Not();
            if (Value.Equals(BigInteger.MinusOne))
                return X.Not();

            if (Value._sign > 0)
            {
                if (X._sign > 0)
                {
                    if (Value._numberLength > X._numberLength)
                        return XorPositive(Value, X);
                    else
                        return XorPositive(X, Value);
                }
                else
                {
                    return XorDiffSigns(Value, X);
                }
            }
            else
            {
                if (X._sign > 0)
                    return XorDiffSigns(X, Value);
                else if (X.FirstNonzeroDigit > Value.FirstNonzeroDigit)
                    return XorNegative(X, Value);
                else
                    return XorNegative(Value, X);
            }
        }
        #endregion

        #region Private Methods
        private static BigInteger AndDiffSigns(BigInteger Positive, BigInteger Negative)
        {
            // PRE: positive is positive and negative is negative
            int iPos = Positive.FirstNonzeroDigit;
            int iNeg = Negative.FirstNonzeroDigit;

            // Look if the trailing zeros of the negative will "blank" all the positive digits
            if (iNeg >= Positive._numberLength)
                return BigInteger.Zero;

            int resLength = Positive._numberLength;
            int[] resDigits = new int[resLength];

            // Must start from max(iPos, iNeg)
            int i = System.Math.Max(iPos, iNeg);
            if (i == iNeg)
            {
                resDigits[i] = -Negative._digits[i] & Positive._digits[i];
                i++;
            }
            int limit = System.Math.Min(Negative._numberLength, Positive._numberLength);
            for (; i < limit; i++)
                resDigits[i] = ~Negative._digits[i] & Positive._digits[i];

            // if the negative was shorter must copy the remaining digits from positive
            if (i >= Negative._numberLength)
            {
                for (; i < Positive._numberLength; i++)
                    resDigits[i] = Positive._digits[i];
            } // else positive ended and must "copy" virtual 0's, do nothing then

            BigInteger result = new BigInteger(1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger AndPositive(BigInteger Value, BigInteger X)
        {
            // PRE: both arguments are positive
            int resLength = System.Math.Min(Value._numberLength, X._numberLength);
            int i = System.Math.Max(Value.FirstNonzeroDigit, X.FirstNonzeroDigit);

            if (i >= resLength)
                return BigInteger.Zero;

            int[] resDigits = new int[resLength];
            for (; i < resLength; i++)
                resDigits[i] = Value._digits[i] & X._digits[i];

            BigInteger result = new BigInteger(1, resLength, resDigits);
            result.CutOffLeadingZeroes();
            return result;
        }

        private static BigInteger AndNegative(BigInteger Longer, BigInteger Shorter)
        {
            // PRE: longer and shorter are negative
            // PRE: longer has at least as many digits as shorter
            int iLonger = Longer.FirstNonzeroDigit;
            int iShorter = Shorter.FirstNonzeroDigit;

            // Does shorter matter?
            if (iLonger >= Shorter._numberLength)
                return Longer;

            int resLength;
            int[] resDigits;
            int i = System.Math.Max(iShorter, iLonger);
            int digit;

            if (iShorter > iLonger)
                digit = -Shorter._digits[i] & ~Longer._digits[i];
            else if (iShorter < iLonger)
                digit = ~Shorter._digits[i] & -Longer._digits[i];
            else
                digit = -Shorter._digits[i] & -Longer._digits[i];

            if (digit == 0)
            {
                for (i++; i < Shorter._numberLength && (digit = ~(Longer._digits[i] | Shorter._digits[i])) == 0; i++)
                {
                    ;  // digit = ~longer.digits[i] & ~shorter.digits[i]
                }
                if (digit == 0)
                {
                    // shorter has only the remaining virtual sign bits
                    for (; i < Longer._numberLength && (digit = ~Longer._digits[i]) == 0; i++)
                    {
                        ;
                    }
                    if (digit == 0)
                    {
                        resLength = Longer._numberLength + 1;
                        resDigits = new int[resLength];
                        resDigits[resLength - 1] = 1;

                        return new BigInteger(-1, resLength, resDigits);
                    }
                }
            }

            resLength = Longer._numberLength;
            resDigits = new int[resLength];
            resDigits[i] = -digit;

            for (i++; i < Shorter._numberLength; i++)
                resDigits[i] = Longer._digits[i] | Shorter._digits[i];

            // shorter has only the remaining virtual sign bits
            for (; i < Longer._numberLength; i++)
                resDigits[i] = Longer._digits[i];

            BigInteger result = new BigInteger(-1, resLength, resDigits);

            return result;
        }

        private static BigInteger AndNotNegative(BigInteger Value, BigInteger X)
        {
            // PRE: val < 0 && that < 0
            int iVal = Value.FirstNonzeroDigit;
            int iThat = X.FirstNonzeroDigit;

            if (iVal >= X._numberLength)
                return BigInteger.Zero;

            int resLength = X._numberLength;
            int[] resDigits = new int[resLength];
            int limit;
            int i = iVal;

            if (iVal < iThat)
            {
                // resDigits[i] = -val.digits[i] & -1;
                resDigits[i] = -Value._digits[i];
                limit = System.Math.Min(Value._numberLength, iThat);
                for (i++; i < limit; i++)
                    resDigits[i] = ~Value._digits[i];

                if (i == Value._numberLength)
                {
                    for (; i < iThat; i++)
                        resDigits[i] = -1;

                    resDigits[i] = X._digits[i] - 1;
                }
                else
                {
                    resDigits[i] = ~Value._digits[i] & (X._digits[i] - 1);
                }
            }
            else if (iThat < iVal)
            {
                resDigits[i] = -Value._digits[i] & X._digits[i];
            }
            else
            {
                resDigits[i] = -Value._digits[i] & (X._digits[i] - 1);
            }

            limit = System.Math.Min(Value._numberLength, X._numberLength);
            for (i++; i < limit; i++)
                resDigits[i] = ~Value._digits[i] & X._digits[i];

            for (; i < X._numberLength; i++)
                resDigits[i] = X._digits[i];

            BigInteger result = new BigInteger(1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger AndNotNegativePositive(BigInteger Negative, BigInteger Positive)
        {
            // PRE: negative < 0 && positive > 0
            int resLength;
            int[] resDigits;
            int limit;
            int digit;
            int iNeg = Negative.FirstNonzeroDigit;
            int iPos = Positive.FirstNonzeroDigit;

            if (iNeg >= Positive._numberLength)
                return Negative;

            resLength = System.Math.Max(Negative._numberLength, Positive._numberLength);
            int i = iNeg;

            if (iPos > iNeg)
            {
                resDigits = new int[resLength];
                limit = System.Math.Min(Negative._numberLength, iPos);
                // 1st case:  resDigits [i] = -(-negative.digits[i] & (~0)) otherwise: resDigits[i] = ~(~negative.digits[i] & ~0)  ;
                for (; i < limit; i++)
                    resDigits[i] = Negative._digits[i];

                if (i == Negative._numberLength)
                {
                    // resDigits[i] = ~(~positive.digits[i] & -1);
                    for (i = iPos; i < Positive._numberLength; i++)
                        resDigits[i] = Positive._digits[i];
                }
            }
            else
            {
                digit = -Negative._digits[i] & ~Positive._digits[i];
                if (digit == 0)
                {
                    limit = System.Math.Min(Positive._numberLength, Negative._numberLength);
                    for (i++; i < limit && (digit = ~(Negative._digits[i] | Positive._digits[i])) == 0; i++)
                    {
                        ; // digit = ~negative.digits[i] & ~positive.digits[i]
                    }
                    if (digit == 0)
                    {
                        // the shorter has only the remaining virtual sign bits
                        for (; i < Positive._numberLength && (digit = ~Positive._digits[i]) == 0; i++)
                        {
                            ; // digit = -1 & ~positive.digits[i]
                        }
                        for (; i < Negative._numberLength && (digit = ~Negative._digits[i]) == 0; i++)
                        {
                            ; // digit = ~negative.digits[i] & ~0
                        }
                        if (digit == 0)
                        {
                            resLength++;
                            resDigits = new int[resLength];
                            resDigits[resLength - 1] = 1;

                            return new BigInteger(-1, resLength, resDigits);
                        }
                    }
                }

                resDigits = new int[resLength];
                resDigits[i] = -digit;
                i++;
            }

            limit = System.Math.Min(Positive._numberLength, Negative._numberLength);
            for (; i < limit; i++)
                resDigits[i] = Negative._digits[i] | Positive._digits[i];

            // Actually one of the next two cycles will be executed
            for (; i < Negative._numberLength; i++)
                resDigits[i] = Negative._digits[i];
            for (; i < Positive._numberLength; i++)
                resDigits[i] = Positive._digits[i];

            BigInteger result = new BigInteger(-1, resLength, resDigits);

            return result;
        }

        private static BigInteger AndNotPositive(BigInteger Value, BigInteger X)
        {
            int[] resDigits = new int[Value._numberLength];
            int limit = System.Math.Min(Value._numberLength, X._numberLength);
            int i;

            for (i = Value.FirstNonzeroDigit; i < limit; i++)
                resDigits[i] = Value._digits[i] & ~X._digits[i];
            for (; i < Value._numberLength; i++)
                resDigits[i] = Value._digits[i];

            BigInteger result = new BigInteger(1, Value._numberLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger AndNotPositiveNegative(BigInteger Positive, BigInteger Negative)
        {
            // PRE: positive > 0 && negative < 0
            int iNeg = Negative.FirstNonzeroDigit;
            int iPos = Positive.FirstNonzeroDigit;

            if (iNeg >= Positive._numberLength)
                return Positive;

            int resLength = System.Math.Min(Positive._numberLength, Negative._numberLength);
            int[] resDigits = new int[resLength];

            // Always start from first non zero of positive
            int i = iPos;

            for (; i < iNeg; i++)
                resDigits[i] = Positive._digits[i];

            if (i == iNeg)
            {
                resDigits[i] = Positive._digits[i] & (Negative._digits[i] - 1);
                i++;
            }
            for (; i < resLength; i++)
                resDigits[i] = Positive._digits[i] & Negative._digits[i];

            BigInteger result = new BigInteger(1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger OrDiffSigns(BigInteger Positive, BigInteger Negative)
        {
            // Jumping over the least significant zero bits
            int iNeg = Negative.FirstNonzeroDigit;
            int iPos = Positive.FirstNonzeroDigit;
            int i;
            int limit;

            // Look if the trailing zeros of the positive will "copy" all
            // the negative digits
            if (iPos >= Negative._numberLength)
                return Negative;

            int resLength = Negative._numberLength;
            int[] resDigits = new int[resLength];

            if (iNeg < iPos)
            {
                // We know for sure that this will be the first non zero digit in the result
                for (i = iNeg; i < iPos; i++)
                    resDigits[i] = Negative._digits[i];
            }
            else if (iPos < iNeg)
            {
                i = iPos;
                resDigits[i] = -Positive._digits[i];
                limit = System.Math.Min(Positive._numberLength, iNeg);

                for (i++; i < limit; i++)
                    resDigits[i] = ~Positive._digits[i];

                if (i != Positive._numberLength)
                {
                    resDigits[i] = ~(-Negative._digits[i] | Positive._digits[i]);
                }
                else
                {
                    for (; i < iNeg; i++)
                        resDigits[i] = -1;

                    resDigits[i] = Negative._digits[i] - 1;
                }
                i++;
            }
            else
            {
                // Applying two complement to negative and to result
                i = iPos;
                resDigits[i] = -(-Negative._digits[i] | Positive._digits[i]);
                i++;
            }
            limit = System.Math.Min(Negative._numberLength, Positive._numberLength);

            // Applying two complement to negative and to result
            for (; i < limit; i++)
                resDigits[i] = Negative._digits[i] & ~Positive._digits[i];
            for (; i < Negative._numberLength; i++)
                resDigits[i] = Negative._digits[i];

            BigInteger result = new BigInteger(-1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger OrNegative(BigInteger Value, BigInteger X)
        {
            // PRE: val and that are negative;
            // PRE: val has at least as many trailing zeros digits as that
            int iThat = X.FirstNonzeroDigit;
            int iVal = Value.FirstNonzeroDigit;
            int i;

            if (iVal >= X._numberLength)
                return X;
            else if (iThat >= Value._numberLength)
                return Value;

            int resLength = System.Math.Min(Value._numberLength, X._numberLength);
            int[] resDigits = new int[resLength];

            // Looking for the first non-zero digit of the result
            if (iThat == iVal)
            {
                resDigits[iVal] = -(-Value._digits[iVal] | -X._digits[iVal]);
                i = iVal;
            }
            else
            {
                for (i = iThat; i < iVal; i++)
                    resDigits[i] = X._digits[i];

                resDigits[i] = X._digits[i] & (Value._digits[i] - 1);
            }

            for (i++; i < resLength; i++)
                resDigits[i] = Value._digits[i] & X._digits[i];

            BigInteger result = new BigInteger(-1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger OrPositive(BigInteger Longer, BigInteger Shorter)
        {
            // longer has at least as many digits as shorter
            int resLength = Longer._numberLength;
            int[] resDigits = new int[resLength];

            int i = System.Math.Min(Longer.FirstNonzeroDigit, Shorter.FirstNonzeroDigit);

            for (i = 0; i < Shorter._numberLength; i++)
                resDigits[i] = Longer._digits[i] | Shorter._digits[i];
            for (; i < resLength; i++)
                resDigits[i] = Longer._digits[i];

            BigInteger result = new BigInteger(1, resLength, resDigits);

            return result;
        }

        private static BigInteger XorDiffSigns(BigInteger Positive, BigInteger Negative)
        {
            int resLength = System.Math.Max(Negative._numberLength, Positive._numberLength);
            int[] resDigits;
            int iNeg = Negative.FirstNonzeroDigit;
            int iPos = Positive.FirstNonzeroDigit;
            int i;
            int limit;

            //The first
            if (iNeg < iPos)
            {
                resDigits = new int[resLength];
                i = iNeg;
                //resDigits[i] = -(-negative.digits[i]);
                resDigits[i] = Negative._digits[i];
                limit = System.Math.Min(Negative._numberLength, iPos);
                //Skip the positive digits while they are zeros
                for (i++; i < limit; i++)
                    resDigits[i] = Negative._digits[i];

                //if the negative has no more elements, must fill the
                //result with the remaining digits of the positive
                if (i == Negative._numberLength)
                {
                    for (; i < Positive._numberLength; i++)
                        resDigits[i] = Positive._digits[i];
                }
            }
            else if (iPos < iNeg)
            {
                resDigits = new int[resLength];
                i = iPos;
                //Applying two complement to the first non-zero digit of the result
                resDigits[i] = -Positive._digits[i];
                limit = System.Math.Min(Positive._numberLength, iNeg);
                //Continue applying two complement the result
                for (i++; i < limit; i++)
                    resDigits[i] = ~Positive._digits[i];

                //When the first non-zero digit of the negative is reached, must apply
                //two complement (arithmetic negation) to it, and then operate
                if (i == iNeg)
                {
                    resDigits[i] = ~(Positive._digits[i] ^ -Negative._digits[i]);
                    i++;
                }
                else
                {
                    //if the positive has no more elements must fill the remaining digits with
                    //the negative ones
                    for (; i < iNeg; i++)
                        resDigits[i] = -1;
                    for (; i < Negative._numberLength; i++)
                        resDigits[i] = Negative._digits[i];
                }
            }
            else
            {
                int digit;
                //The first non-zero digit of the positive and negative are the same
                i = iNeg;
                digit = Positive._digits[i] ^ -Negative._digits[i];
                if (digit == 0)
                {
                    limit = System.Math.Min(Positive._numberLength, Negative._numberLength);
                    for (i++; i < limit && (digit = Positive._digits[i] ^ ~Negative._digits[i]) == 0; i++)
                        ;
                    if (digit == 0)
                    {
                        // shorter has only the remaining virtual sign bits
                        for (; i < Positive._numberLength && (digit = ~Positive._digits[i]) == 0; i++)
                        {
                            ;
                        }
                        for (; i < Negative._numberLength && (digit = ~Negative._digits[i]) == 0; i++)
                        {
                            ;
                        }
                        if (digit == 0)
                        {
                            resLength = resLength + 1;
                            resDigits = new int[resLength];
                            resDigits[resLength - 1] = 1;

                            return new BigInteger(-1, resLength, resDigits);
                        }
                    }
                }
                resDigits = new int[resLength];
                resDigits[i] = -digit;
                i++;
            }

            limit = System.Math.Min(Negative._numberLength, Positive._numberLength);
            for (; i < limit; i++)
                resDigits[i] = ~(~Negative._digits[i] ^ Positive._digits[i]);
            for (; i < Positive._numberLength; i++)
                resDigits[i] = Positive._digits[i];
            for (; i < Negative._numberLength; i++)
                resDigits[i] = Negative._digits[i];

            BigInteger result = new BigInteger(-1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger XorNegative(BigInteger Value, BigInteger X)
        {
            // PRE: val and that are negative
            // PRE: val has at least as many trailing zero digits as that
            int resLength = System.Math.Max(Value._numberLength, X._numberLength);
            int[] resDigits = new int[resLength];
            int iVal = Value.FirstNonzeroDigit;
            int iThat = X.FirstNonzeroDigit;
            int i = iThat;
            int limit;


            if (iVal == iThat)
            {
                resDigits[i] = -Value._digits[i] ^ -X._digits[i];
            }
            else
            {
                resDigits[i] = -X._digits[i];
                limit = System.Math.Min(X._numberLength, iVal);
                for (i++; i < limit; i++)
                    resDigits[i] = ~X._digits[i];

                // Remains digits in that?
                if (i == X._numberLength)
                {
                    //Jumping over the remaining zero to the first non one
                    for (; i < iVal; i++)
                        resDigits[i] = -1;

                    resDigits[i] = Value._digits[i] - 1;
                }
                else
                {
                    resDigits[i] = -Value._digits[i] ^ ~X._digits[i];
                }
            }

            limit = System.Math.Min(Value._numberLength, X._numberLength);
            //Perform ^ between that al val until that ends
            for (i++; i < limit; i++)
                resDigits[i] = Value._digits[i] ^ X._digits[i];

            //Perform ^ between val digits and -1 until val ends
            for (; i < Value._numberLength; i++)
                resDigits[i] = Value._digits[i];
            for (; i < X._numberLength; i++)
                resDigits[i] = X._digits[i];

            BigInteger result = new BigInteger(1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }

        private static BigInteger XorPositive(BigInteger Longer, BigInteger Shorter)
        {
            // PRE: longer and shorter are positive;
            // PRE: longer has at least as many digits as shorter
            int resLength = Longer._numberLength;
            int[] resDigits = new int[resLength];
            int i = System.Math.Min(Longer.FirstNonzeroDigit, Shorter.FirstNonzeroDigit);

            for (; i < Shorter._numberLength; i++)
                resDigits[i] = Longer._digits[i] ^ Shorter._digits[i];
            for (; i < Longer._numberLength; i++)
                resDigits[i] = Longer._digits[i];

            BigInteger result = new BigInteger(1, resLength, resDigits);
            result.CutOffLeadingZeroes();

            return result;
        }
        #endregion
    }
}