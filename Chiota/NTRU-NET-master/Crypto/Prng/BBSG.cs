#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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
    /// <h3>An implementation of a Blum-Blum-Shub random number generator.</h3>
    /// <para>Implements BBSG as defined in the NIST document: SP800-22 1a<cite>SP800-22A</cite>, Section D.8</para>
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
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-22 1a, Section D.3: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST SP800-90B: <cite>SP800-90B</cite>Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST Fips 140-2: <cite>Fips 140-2</cite>Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>RFC 4086: <cite>RFC 4086</cite>Randomness Requirements for Security.</description></item>
    /// <item><description>Cryptographic Secure Pseudo-Random Bits Generation: <cite>Blum-Blum-Shub</cite>The Blum-Blum-Shub Generator.</description></item>
    /// <item><description>Handbook of Applied Cryptography Chapter 5<cite>Handbook of Applied Cryptography</cite>: Pseudorandom Bits and Sequences.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>This code based on the excellent Java version by Zur Aougav: <see href="http://sourceforge.net/projects/jrandtest/">BBSPrng</see> class.</description></item>
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
        private bool _isDisposed = false;
        private BigInteger _N;
        private BigInteger _P;
        private BigInteger _Q;
        private BigInteger _X;
        private BigInteger _X0;
        private SecureRandom _secRand;
        #endregion

        #region Properties
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
            _secRand = new SecureRandom();

            Initialize(N_BITS);
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="BitLength">Length of integers used in equations, must be at least 512 bits</param>
        public BBSG(int BitLength)
        {
            _secRand = new SecureRandom();

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

            _secRand = new SecureRandom();

            _P = P;
            _X = X;
            _N = N;
            _Q = Q;
            _X0 = X;
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
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            int reqSize = Data.Length;
            int algSize = (reqSize % LONG_SIZE == 0 ? reqSize : reqSize + LONG_SIZE - (reqSize % LONG_SIZE));
            int lstBlock = algSize - LONG_SIZE;
            Int64[] rndNum = new Int64[1];

            for (int i = 0; i < algSize; i += LONG_SIZE)
            {
                // get 8 bytes
                rndNum[0] = NextLong();

                // copy to output
                if (i != lstBlock)
                {
                    // copy in the int bytes
                    Buffer.BlockCopy(rndNum, 0, Data, i, LONG_SIZE);
                }
                else
                {
                    // final copy
                    int fnlSize = (reqSize % LONG_SIZE) == 0 ? LONG_SIZE : (reqSize % LONG_SIZE);
                    Buffer.BlockCopy(rndNum, 0, Data, i, fnlSize);
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
        /// <returns>Random Int32</returns>
        public Int32 Next()
        {
            // Xi+1 = (X pow 2) mod N
            _X = _X.Multiply(_X).Mod(_N);

            return _X.ToInt32();
        }

        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next(int Maximum)
        {
            byte[] rand;
            Int32[] num = new Int32[1];

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
        /// <returns>Random Int32</returns>
        public Int32 Next(int Minimum, int Maximum)
        {
            Int32 num = 0;
            while ((num = Next(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Get a pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random Int64</returns>
        public long NextLong()
        {
            // Xi+1 = (X pow 2) mod N
            _X = _X.Multiply(_X).Mod(_N);

            return _X.ToInt64();
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong(long Maximum)
        {
            byte[] rand;
            Int64[] num = new Int64[1];

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
        /// <returns>Random Int64</returns>
        public Int64 NextLong(long Minimum, long Maximum)
        {
            Int64 num = 0;
            while ((num = NextLong(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Sets or resets the internal state
        /// </summary>
        public void Reset()
        {
            _X = _X0;
        }
        #endregion

        #region Private Methods
        private byte[] GetByteRange(Int64 Maximum)
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

        private byte[] GetBits(byte[] Data, Int64 Maximum)
        {
            UInt64[] val = new UInt64[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > (UInt64)Maximum && bits > 0)
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
            _P = BigInteger.ProbablePrime(BitLength, _secRand);
            _Q = BigInteger.ProbablePrime(BitLength, _secRand);
            // N = P * Q
            _N = _P.Multiply(_Q);
            // get X
            _X = BigInteger.ValueOf(_secRand.NextInt64());

            // find random X mod N
            for (int i = 0; i < 10 || _X.CompareTo(BigInteger.One) < 1; i++)
                _X = _X.Multiply(BigInteger.ValueOf(_secRand.NextInt64())).Mod(_N);

            // X = (X pow 2) mod N
            _X = _X.Multiply(_X).Mod(_N);
            // store X
            _X0 = _X;
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_secRand != null)
                    {
                        _secRand.Dispose();
                        _secRand = null;
                    }
                    if (_N != null)
                        _N = null;
                    if (_P != null)
                        _P = null;
                    if (_Q != null)
                        _Q = null;
                    if (_X != null)
                        _X = null;
                    if (_X0 != null)
                        _X0 = null;
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
