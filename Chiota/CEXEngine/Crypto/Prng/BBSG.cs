#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Implementation Details:
// An implementation of a Blum-Blum-Shub random number generator.
// Written by John Underhill, January 05, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng 
{
    /// <summary>
    /// BBSG: An implementation of a Blum-Blum-Shub random number generator
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (IRandom rnd = new BBSG())
    ///     x = rnd.Next();
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>, Section D.3: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
    /// <item><description>Cryptographic <a href="http://crypto.junod.info/bbs.pdf">Secure Pseudo-Random Bits Generation</a>: The Blum-Blum-Shub Generator.</description></item>
    /// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/">Chapter 5</a>: Pseudorandom Bits and Sequences.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>This code based on the excellent Java version by Zur Aougav: <a href="http://sourceforge.net/projects/jrandtest/">BBSPrng</a> class.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class BBSG : IRandom
    {
        #region Constants
        private const string ALG_NAME = "BBSG";
        private const int LONG_SIZE = 8;
        private const int N_BITS = 512;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private BigInteger m_N;
        private BigInteger m_P;
        private BigInteger m_Q;
        private BigInteger m_X;
        private BigInteger m_X0;
        private SecureRandom m_secRand;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The prngs type name
        /// </summary>
        public Prngs Enumeral
        {
            get { return Prngs.BBSG; }
        }

        /// <summary>
        /// Algorithm name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        public BBSG()
        {
            m_secRand = new SecureRandom();

            Initialize(N_BITS);
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="BitLength">Length of integers used in equations, must be at least 512 bits</param>
        public BBSG(int BitLength)
        {
            m_secRand = new SecureRandom();

            if (BitLength < N_BITS)
                Initialize(N_BITS);
            else
                Initialize(BitLength);
        }

        /// <summary>
        /// Initialize class with Primes, and State Seed values. Values must be probable primes.
        /// </summary>
        /// 
        /// <param name="X">Random Generator State (X = X ** 2 mod N)</param>
        /// <param name="P">P Random Prime</param>
        /// <param name="Q">Q Random Prime</param>
        /// <param name="N">Random Prime (N = P * Q)</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if P or Q is not a valid prime</exception>
        public BBSG(BigInteger X, BigInteger P, BigInteger Q, BigInteger N)
        {
            if (!P.IsProbablePrime(90))
                throw new CryptoRandomException("BBSG:Ctor", "P is not a valid prime number!", new ArgumentOutOfRangeException());
            if (!Q.IsProbablePrime(90))
                throw new CryptoRandomException("BBSG:Ctor", "Q is not a valid prime number!", new ArgumentOutOfRangeException());

            m_secRand = new SecureRandom();

            m_P = P;
            m_X = X;
            m_N = N;
            m_Q = Q;
            m_X0 = X;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~BBSG()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Array to fill with random bytes</param>
        public void GetBytes(byte[] Output)
        {
            int reqSize = Output.Length;
            int algSize = (reqSize % LONG_SIZE == 0 ? reqSize : reqSize + LONG_SIZE - (reqSize % LONG_SIZE));
            int lstBlock = algSize - LONG_SIZE;
            long[] rndNum = new long[1];

            for (int i = 0; i < algSize; i += LONG_SIZE)
            {
                // get 8 bytes
                rndNum[0] = NextLong();

                // copy to output
                if (i != lstBlock)
                {
                    // copy in the int bytes
                    Buffer.BlockCopy(rndNum, 0, Output, i, LONG_SIZE);
                }
                else
                {
                    // final copy
                    int fnlSize = (reqSize % LONG_SIZE) == 0 ? LONG_SIZE : (reqSize % LONG_SIZE);
                    Buffer.BlockCopy(rndNum, 0, Output, i, fnlSize);
                }
            }
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];

            GetBytes(data);

            return data;
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
        public int Next()
        {
            // Xi+1 = (X pow 2) mod N
            m_X = m_X.Multiply(m_X).Mod(m_N);

            return m_X.ToInt32();
        }

        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random int</returns>
        public int Next(int Maximum)
        {
            byte[] rand;
            int[] num = new int[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random int</returns>
        public int Next(int Minimum, int Maximum)
        {
            int num = 0;
            while ((num = Next(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Get a pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random long</returns>
        public long NextLong()
        {
            // Xi+1 = (X pow 2) mod N
            m_X = m_X.Multiply(m_X).Mod(m_N);

            return m_X.ToInt64();
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        public long NextLong(long Maximum)
        {
            byte[] rand;
            long[] num = new long[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        public long NextLong(long Minimum, long Maximum)
        {
            long num = 0;
            while ((num = NextLong(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Sets or resets the internal state
        /// </summary>
        public void Reset()
        {
            m_X = m_X0;
        }
        #endregion

        #region Private Methods
        private byte[] GetByteRange(long Maximum)
        {
            byte[] data;

            if (Maximum < 256)
                data = GetBytes(1);
            else if (Maximum < 65536)
                data = GetBytes(2);
            else if (Maximum < 16777216)
                data = GetBytes(3);
            else if (Maximum < 4294967296)
                data = GetBytes(4);
            else if (Maximum < 1099511627776)
                data = GetBytes(5);
            else if (Maximum < 281474976710656)
                data = GetBytes(6);
            else if (Maximum < 72057594037927936)
                data = GetBytes(7);
            else
                data = GetBytes(8);

            return GetBits(data, Maximum);
        }

        private byte[] GetBits(byte[] Data, long Maximum)
        {
            ulong[] val = new ulong[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > (ulong)Maximum && bits > 0)
            {
                val[0] >>= 1;
                bits--;
            }

            byte[] ret = new byte[Data.Length];
            Buffer.BlockCopy(val, 0, ret, 0, Data.Length);

            return ret;
        }

        private void Initialize(int BitLength)
        {
            // get primes P and Q
            m_P = BigInteger.ProbablePrime(BitLength, m_secRand);
            m_Q = BigInteger.ProbablePrime(BitLength, m_secRand);
            // N = P * Q
            m_N = m_P.Multiply(m_Q);
            // get X
            m_X = BigInteger.ValueOf(m_secRand.NextInt64());

            // find random X mod N
            for (int i = 0; i < 10 || m_X.CompareTo(BigInteger.One) < 1; i++)
                m_X = m_X.Multiply(BigInteger.ValueOf(m_secRand.NextInt64())).Mod(m_N);

            // X = (X pow 2) mod N
            m_X = m_X.Multiply(m_X).Mod(m_N);
            // store X
            m_X0 = m_X;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (m_secRand != null)
                    {
                        m_secRand.Dispose();
                        m_secRand = null;
                    }
                    if (m_N != null)
                        m_N = null;
                    if (m_P != null)
                        m_P = null;
                    if (m_Q != null)
                        m_Q = null;
                    if (m_X != null)
                        m_X = null;
                    if (m_X0 != null)
                        m_X0 = null;
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
