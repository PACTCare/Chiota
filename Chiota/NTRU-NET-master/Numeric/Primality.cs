#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Prng ;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric 
{
    /// <summary>
    /// Provides primality probabilistic methods
    /// </summary>
    internal sealed class Primality
    {
        #region Private Fields
        //All prime numbers with bit length lesser than 10 bits
        private static readonly int[] _primes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
            31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
            103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
            173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
            241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
            317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
            401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
            479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
            571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
            647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
            739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823,
            827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
            919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009,
            1013, 1019, 1021 };

        // All BigInteger prime numbers with bit length lesser than 8 bits
        private static readonly BigInteger[] _biPrimes = new BigInteger[_primes.Length];

        // It encodes how many iterations of Miller-Rabin test are need to get an
        // error bound not greater than 2 pow (-100).
        // For example: for a 1000-bit number we need 4 iterations, since BITS[3] &lt; 1000 &lt;= BITS[4].
        private static readonly int[] BITS = { 0, 0, 1854, 1233, 927, 747, 627, 543,
            480, 431, 393, 361, 335, 314, 295, 279, 265, 253, 242, 232, 223,
            216, 181, 169, 158, 150, 145, 140, 136, 132, 127, 123, 119, 114,
            110, 105, 101, 96, 92, 87, 83, 78, 73, 69, 64, 59, 54, 49, 44, 38,
            32, 26, 1 };

        // It encodes how many i-bit primes there are in the table for
        // i=2,...,10. For example offsetPrimes[6] says that from
        // index 11 exists 7 consecutive 6-bit prime numbers in the array.
        private static readonly int[][] _offsetPrimes;

        #endregion

        #region Constructors
        static Primality()
        {
            // To initialize the dual table of BigInteger primes
            for (int i = 0; i < _primes.Length; i++)
                _biPrimes[i] = BigInteger.ValueOf(_primes[i]);

            _offsetPrimes = new int[11][];
            _offsetPrimes[0] = null;
            _offsetPrimes[1] = null;
            _offsetPrimes[2] = new int[] { 0, 2 };
            _offsetPrimes[3] = new int[] { 2, 2 };
            _offsetPrimes[4] = new int[] { 4, 2 };
            _offsetPrimes[5] = new int[] { 6, 5 };
            _offsetPrimes[6] = new int[] { 11, 7 };
            _offsetPrimes[7] = new int[] { 18, 13 };
            _offsetPrimes[8] = new int[] { 31, 23 };
            _offsetPrimes[9] = new int[] { 54, 43 };
            _offsetPrimes[10] = new int[] { 97, 75 };
        }

        private Primality()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// It uses the sieve of Eratosthenes to discard several composite numbers in 
        /// some appropriate range (at the moment [this, this + 1024]).
        /// <para>After this process it applies the Miller-Rabin test to the numbers that were not discarded in the sieve.</para>
        /// </summary>
        internal static BigInteger NextProbablePrime(BigInteger X)
        {
            // PRE: n >= 0
            int i, j;
            int certainty;
            int gapSize = 1024; // for searching of the next probable prime number
            int[] modules = new int[_primes.Length];
            bool[] isDivisible = new bool[gapSize];
            BigInteger startPoint;
            BigInteger probPrime;
            // If n < "last prime of table" searches next prime in the table
            if ((X._numberLength == 1) && (X._digits[0] >= 0) && (X._digits[0] < _primes[_primes.Length - 1]))
            {
                for (i = 0; X._digits[0] >= _primes[i]; i++)
                {
                    ;
                }

                return _biPrimes[i];
            }
            // Creates a "N" enough big to hold the next probable prime Note that: N < "next prime" < 2*N
            startPoint = new BigInteger(1, X._numberLength, new int[X._numberLength + 1]);
            Array.Copy(X._digits, 0, startPoint._digits, 0, X._numberLength);

            // To fix N to the "next odd number"
            if (X.TestBit(0))
                Elementary.InplaceAdd(startPoint, 2);
            else
                startPoint._digits[0] |= 1;

            // To set the improved certainly of Miller-Rabin
            j = startPoint.BitLength;
            for (certainty = 2; j < BITS[certainty]; certainty++)
            {
                ;
            }
            // To calculate modules: N mod p1, N mod p2, ... for first primes.
            for (i = 0; i < _primes.Length; i++)
                modules[i] = Division.Remainder(startPoint, _primes[i]) - gapSize;

            while (true)
            {
                // At this point, all numbers in the gap are initialized as probably primes
                for (int k = 0; k < isDivisible.Length; k++)
                    isDivisible[k] = false;

                // To discard multiples of first primes
                for (i = 0; i < _primes.Length; i++)
                {
                    modules[i] = (modules[i] + gapSize) % _primes[i];
                    j = (modules[i] == 0) ? 0 : (_primes[i] - modules[i]);

                    for (; j < gapSize; j += _primes[i])
                        isDivisible[j] = true;
                }
                // To execute Miller-Rabin for non-divisible numbers by all first
                // primes
                for (j = 0; j < gapSize; j++)
                {
                    if (!isDivisible[j])
                    {
                        probPrime = startPoint.Copy();
                        Elementary.InplaceAdd(probPrime, j);

                        if (MillerRabin(probPrime, certainty))
                            return probPrime;
                    }
                }
                Elementary.InplaceAdd(startPoint, gapSize);
            }
        }

        /// <summary>
        /// A random number is generated until a probable prime number is found
        /// </summary>
        internal static BigInteger ConsBigInteger(int BitLength, int Certainty, SecureRandom Rnd)
        {
            // PRE: bitLength >= 2;
            // For small numbers get a random prime from the prime table
            if (BitLength <= 10)
            {
                int[] rp = _offsetPrimes[BitLength];
                return _biPrimes[rp[0] + Rnd.NextInt32(rp[1])];
            }
            int shiftCount = (-BitLength) & 31;
            int last = (BitLength + 31) >> 5;
            BigInteger n = new BigInteger(1, last, new int[last]);

            last--;
            do
            {// To fill the array with random integers
                for (int i = 0; i < n._numberLength; i++)
                    n._digits[i] = Rnd.Next();
                
                // To fix to the correct bitLength
                // n.digits[last] |= 0x80000000;
                n._digits[last] |= Int32.MinValue;
                n._digits[last] = IntUtils.URShift(n._digits[last], shiftCount);
                // To create an odd number
                n._digits[0] |= 1;
            } while (!IsProbablePrime(n, Certainty));

            return n;
        }

        /// <summary>
        /// Tests whether this BigInteger is probably prime.
        /// <para>If true is returned, then this is prime with a probability beyond <c>(1-1/2^certainty)</c>.
        /// If false is returned, then this is definitely composite.
        /// If the argument Certainty &lt;= 0, then this method returns true.</para>
        /// </summary>
        /// 
        /// <param name="X">BigInteger to test</param>
        /// <param name="Certainty">Tolerated primality uncertainty</param>
        /// 
        /// <returns>Returns true, if this is probably prime, false  otherwise</returns>
        internal static bool IsProbablePrime(BigInteger X, int Certainty)
        {
            // PRE: n >= 0;
            if ((Certainty <= 0) || ((X._numberLength == 1) && (X._digits[0] == 2)))
                return true;
            
            // To discard all even numbers
            if (!X.TestBit(0))
                return false;
            
            // To check if 'n' exists in the table (it fit in 10 bits)
            if ((X._numberLength == 1) && ((X._digits[0] & 0XFFFFFC00) == 0))
                return (Array.BinarySearch(_primes, X._digits[0]) >= 0);
            
            // To check if 'n' is divisible by some prime of the table
            for (int j = 1; j < _primes.Length; j++)
            {
                if (Division.RemainderArrayByInt(X._digits, X._numberLength, _primes[j]) == 0)
                    return false;
            }
            // To set the number of iterations necessary for Miller-Rabin test
            int i;
            int bitLength = X.BitLength;

            for (i = 2; bitLength < BITS[i]; i++)
            {
                ;
            }
            Certainty = System.Math.Min(i, 1 + ((Certainty - 1) >> 1));

            return MillerRabin(X, Certainty);
        }
        #endregion

        #region Private Methods
        private static bool MillerRabin(BigInteger X, int T)
        {
            // The Miller-Rabin primality test
            // n >= 0, t >= 0
            BigInteger x; // x := UNIFORM{2...n-1}
            BigInteger y; // y := x^(q * 2^j) mod n
            BigInteger n_minus_1 = X.Subtract(BigInteger.One); // n-1
            int bitLength = n_minus_1.BitLength; // ~ log2(n-1)
            // (q,k) such that: n-1 = q * 2^k and q is odd
            int k = n_minus_1.LowestSetBit;
            BigInteger q = n_minus_1.ShiftRight(k);
            SecureRandom rnd = new SecureRandom();

            for (int i = 0; i < T; i++)
            {
                // To generate a witness 'x', first it use the primes of table
                if (i < _primes.Length)
                {
                    x = _biPrimes[i];
                }
                else
                {
                    // It generates random witness only if it's necesssary. 
                    // Note that all methods would call Miller-Rabin with t <= 50 so this part is only to do more robust the algorithm
                    do
                    {
                        x = new BigInteger(bitLength, rnd);
                    } while ((x.CompareTo(X) >= BigInteger.EQUALS) || (x._sign == 0) || x.IsOne());
                }
                y = x.ModPow(q, X);
                if (y.IsOne() || y.Equals(n_minus_1))
                    continue;
                
                for (int j = 1; j < k; j++)
                {
                    if (y.Equals(n_minus_1))
                        continue;
                    
                    y = y.Multiply(y).Mod(X);

                    if (y.IsOne())
                        return false;
                }
                if (!y.Equals(n_minus_1))
                    return false;
            }
            return true;
        }
        #endregion
    }
}