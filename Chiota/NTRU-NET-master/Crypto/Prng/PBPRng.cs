#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
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
    /// <h3>An implementation of a passphrase based PKCS#5 random number generator.</h3>
    /// <para>Implements PKCS#5 as defined in RFC 2898</para>
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (IRandom rnd = new PBPRng(new SHA512(), PassPhrase, Salt))
    ///     x = rnd.Next();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/28/15" version="1.3.2.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mac.HMAC">VTDev.Libraries.CEXEngine.Crypto.Mac HMAC</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>RFC 2898: <see href="http://tools.ietf.org/html/rfc2898">Specification</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class PBPRng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "PassphrasePrng";
        private const int INT_SIZE = 4;
        private const int LONG_SIZE = 8;
        private const int PKCS_ITERATIONS = 10000;
        #endregion

        #region Fields
        private IDigest _digest;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private int _position;
        private byte[] _rndData;
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
        /// Creates a new PassphrasePrng from a passphrase and salt,
        /// and seeds it with the output of PKCS5
        /// </summary>
        /// 
        /// <param name="Digest">Digest engine</param>
        /// <param name="Passphrase">The passphrase</param>
        /// <param name="Salt">The salt value</param>
        /// <param name="Iterations">The number of transformation iterations performed by the digest with PKCS5 (default is 10,000)</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called (default is true)</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if a null Digest, Passphrase or Salt are used</exception>
        public PBPRng(IDigest Digest, byte[] Passphrase, byte[] Salt, int Iterations = PKCS_ITERATIONS, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoRandomException("PBPRng:Ctor", "Digest can not be null!", new ArgumentNullException());
            if (Passphrase == null)
                throw new CryptoRandomException("PBPRng:Ctor", "Passphrase can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoRandomException("PBPRng:Ctor", "Salt can not be null!", new ArgumentNullException());

            try
            {
                _disposeEngine = DisposeEngine;
                PKCS5 pkcs = new PKCS5(Digest, Iterations, false);
                _digest = Digest;
                pkcs.Initialize(Salt, Passphrase);
                _rndData = new byte[_digest.BlockSize];
                pkcs.Generate(_rndData);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }

            _position = 0;
        }

        private PBPRng()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PBPRng()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Creates a new Passphrase rng whose output differs but is a
        /// function of this rng's internal state.
        /// </summary>
        /// 
        /// <param name="Digest">The digest instance</param>
        /// 
        /// <returns>Returns a PassphrasePrng instance</returns>
        public PBPRng CreateBranch(IDigest Digest)
        {
            PBPRng branch = new PBPRng();

            try
            {
                branch._digest = Digest;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }

            branch._rndData = (byte[])_rndData.Clone();
            branch._rndData[0]++;

            return branch;
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            int reqSize = Data.Length;
            int algSize = (reqSize % INT_SIZE == 0 ? reqSize : reqSize + INT_SIZE - (reqSize % INT_SIZE));
            int lstBlock = algSize - INT_SIZE;
            Int32[] rndNum = new Int32[1];

            for (int i = 0; i < algSize; i += INT_SIZE)
            {
                // get 8 bytes
                rndNum[0] = Next();

                // copy to output
                if (i != lstBlock)
                {
                    // copy in the int bytes
                    Buffer.BlockCopy(rndNum, 0, Data, i, INT_SIZE);
                }
                else
                {
                    // final copy
                    int fnlSize = (reqSize % INT_SIZE) == 0 ? INT_SIZE : (reqSize % INT_SIZE);
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
        public int Next()
        {
            int value = 0;
            for (int i = 0; i < 32; i += 8)
            {
                if (_position >= _rndData.Length)
                {
                    _rndData = _digest.ComputeHash(_rndData);
                    _position = 0;
                }
                value = (value << 8) | (_rndData[_position] & 0xFF);
                _position++;
            }

            return value;
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
            Int64[] data = new Int64[1];
            Buffer.BlockCopy(GetBytes(8), 0, data, 0, LONG_SIZE);

            return data[0];
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
            Array.Clear(_rndData, 0, _rndData.Length);
            _digest.Reset();
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
                if (_digest != null && _disposeEngine)
                {
                    _digest.Dispose();
                    _digest = null;
                }
                if (_rndData != null)
                {
                    Array.Clear(_rndData, 0, _rndData.Length);
                    _rndData = null;
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
