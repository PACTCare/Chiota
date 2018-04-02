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
// An implementation of the Quadratic Congruential Generator II: QCG-2.
// Written by John Underhill, January 10, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>An implementation of a Quadratic Congruential Generator II random number generator : QCG-II.</h3>
    /// <para>Implements QCGII as defined in the NIST document: SP800-22 1a<cite>SP800-22A</cite>, Section D.3</para>
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (IRandom rnd = new QCG2())
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
    /// </list> 
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>This code based on the excellent Java version by Zur Aougav: <see href="http://sourceforge.net/projects/jrandtest/">QuadraidResidue2Prng</see> class.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class QCG2 : IRandom
    {
        #region Constants
        private const string ALG_NAME = "QCG2";
        private const int G_BITS = 512;
        private const int LONG_SIZE = 8;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private SecureRandom _secRand;
        private BigInteger _BI3 = BigInteger.ValueOf(3);
        private BigInteger _G;
        private BigInteger _G0;
        private BigInteger _P;
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
        public QCG2()
        {
            _secRand = new SecureRandom();

            Initialize(G_BITS);
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="BitLength">Length of integers used in equations; must be at least 512 bits</param>
        public QCG2(int BitLength)
        {
            _secRand = new SecureRandom();

            if (BitLength < G_BITS)
                Initialize(G_BITS);
            else
                Initialize(BitLength);
        }

        /// <summary>
        /// Initialize class with Prime and State Seed values. Values must be probable primes.
        /// </summary>
        /// 
        /// <param name="P">Random Prime with probability &lt; 2 ** -100</param>
        /// <param name="G">Random Generator State</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if P is not a valid prime</exception>
        public QCG2(BigInteger P, BigInteger G)
        {
            if (!P.IsProbablePrime(90))
                throw new CryptoRandomException("QCG2:Ctor", "P is not a valid prime number!", new ArgumentOutOfRangeException());

            _secRand = new SecureRandom();

            _P = P;
            _G = G;
            _G0 = G;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~QCG2()
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
            byte[] rand = new byte[Size];

            GetBytes(rand);

            return rand;
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next()
        {
            // Xi+1 = (2Xi pow 2) + 3Xi + (1 mod P)
            _G = _G.Multiply(_G.Add(_G).Add(_BI3)).Add(BigInteger.One).Mod(_P);

            // set G to 2 if G <= 1
            if (_G.CompareTo(BigInteger.One) < 1)
                _G = BigInteger.ValueOf(2);

            return _G.ToInt32();
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
        public Int64 NextLong()
        {
            // Xi+1 = (2Xi pow 2) + 3Xi + (1 mod P)
            _G = _G.Multiply(_G.Add(_G).Add(_BI3)).Add(BigInteger.One).Mod(_P);

            // set G to 2 if G <= 1
            if (_G.CompareTo(BigInteger.One) < 1)
                _G = BigInteger.ValueOf(2);

            return _G.ToInt64();
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
        /// Resets the internal state
        /// </summary>
        public void Reset()
        {
            _G = _G0;
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
            _P = BigInteger.ProbablePrime(BitLength, _secRand);
            _G = BigInteger.ProbablePrime(BitLength, _secRand);

            // if G >= P swap(G, P)
            if (_G.CompareTo(_P) > -1)
            {
                BigInteger temp = _G;
                _G = _P;
                _P = temp;
            }

            _G0 = _G;
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

                    if (_BI3 != null)
                        _BI3 = null;
                    if (_G != null)
                        _G = null;
                    if (_G0 != null)
                        _G0 = null;
                    if (_P != null)
                        _P = null;
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
