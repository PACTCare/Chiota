#region Directives
using System;
using System.Security.Cryptography;
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
// An implementation of a Cryptographically Secure Pseudo Random Number Generator (SecureRandom). 
// Uses the <see href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</see> class to produce pseudo random output.
// Written by John Underhill, January 6, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>An implementation of a Cryptographically Secure Pseudo Random Number Generator: SecureRandom.</h3> 
    /// 
    /// <para>Uses the RNGCryptoServiceProvider<cite>RNGCryptoServiceProvider</cite> class to generate non-negative random numbers.</para>
    /// </summary>
    /// 
    /// <example>
    /// <c>
    /// int x;
    /// using (SecureRandom rnd = new SecureRandom())
    ///     x = rnd.NextInt32();
    /// </c>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/04/28" version="1.4.0.0">Added thread safety</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    public sealed class SecureRandom : IDisposable
    {
        #region Constants
        private const UInt16 MAXD16 = 16368;
        private const int BUFFER_SIZE = 1024;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private RNGCryptoServiceProvider _rngEngine;
        private byte[] _byteBuffer;
        private int _bufferIndex = 0;
        private int _bufferSize = 0;
        private object _objLock = new object();
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="BufferSize">Size of the internal buffer; must be more than zero</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if a zero size buffer is used</exception>
        public SecureRandom(int BufferSize = BUFFER_SIZE)
        {
            if (BufferSize < 1)
                throw new CryptoRandomException("SecureRandom:Ctor", "The buffer size must be more than zero!", new ArgumentException());

            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SecureRandom()
        {
            Dispose(false);
        }
        #endregion

        #region Reset
        /// <summary>
        /// Reset the RNGCryptoServiceProvider instance.
        /// </summary>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if RNGCryptoServiceProvider initialization failed</exception>
        public void Reset()
        {
            lock (_objLock)
            {
                if (_rngEngine != null)
                {
                    _rngEngine.Dispose();
                    _rngEngine = null;
                }

                try
                {
                    _rngEngine = new RNGCryptoServiceProvider();
                }
                catch (Exception ex)
                {
                    if (_rngEngine == null)
                        throw new CryptoRandomException("SecureRandom:Reset", "RNGCrypto could not be initialized!", ex);
                }

                _rngEngine.GetBytes(_byteBuffer);
                _bufferIndex = 0;
            }
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Algorithm Name
        /// </summary>
        public string Name
        {
            get { return "SecureRandom"; }
        }
        #endregion

        #region Char
        /// <summary>
        /// Get a random char
        /// </summary>
        /// 
        /// <returns>Random char</returns>
        public char NextChar()
        {
            return BitConverter.ToChar(GetBytes(2), 0);
        }
        #endregion

        #region Double
        /// <summary>
        /// Get a non-ranged random double
        /// </summary>
        /// 
        /// <returns>Random double</returns>
        public double AnyDouble()
        {
            return BitConverter.ToDouble(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random double in the range 0.0 to 1.0
        /// </summary>
        /// 
        /// <returns>Random double</returns>
        public double NextDouble()
        {
            double[] num = new double[1];
            UInt16[] mnv = new UInt16[1];

            mnv[0] = NextUInt16(MAXD16);
            Buffer.BlockCopy(mnv, 0, num, 6, 2);

            return num[0];
        }
        #endregion

        #region Int16
        /// <summary>
        /// Get a random non-negative short integer
        /// </summary>
        /// 
        /// <returns>Random Int16</returns>
        public Int16 NextInt16()
        {
            return BitConverter.ToInt16(GetBytes(2), 0);
        }

        /// <summary>
        /// Get a random non-negative short integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <returns>Random Int16</returns>
        public Int16 NextInt16(Int16 Maximum)
        {
            byte[] rand;
            Int16[] num = new Int16[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1)
                num[0] = 0;

            return num[0];
        }

        /// <summary>
        /// Get a random non-negative short integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int16</returns>
        public Int16 NextInt16(Int16 Minimum, Int16 Maximum)
        {
            Int16 num = 0;
            while ((num = NextInt16(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region UInt16
        /// <summary>
        /// Get a random unsigned short integer
        /// </summary>
        /// 
        /// <returns>Random UInt16</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16()
        {
            return BitConverter.ToUInt16(GetBytes(2), 0);
        }

        /// <summary>
        /// Get a random unsigned short integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt16</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16(UInt16 Maximum)
        {
            byte[] rand;
            UInt16[] num = new UInt16[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a random unsigned short integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16(UInt16 Minimum, UInt16 Maximum)
        {
            UInt16 num = 0;
            while ((num = NextUInt16(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region Int32
        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 NextInt32()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 NextInt32(Int32 Maximum)
        {
            byte[] rand;
            Int32[] num = new Int32[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1)
                num[0] = 0;

            return num[0];
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 NextInt32(Int32 Minimum, Int32 Maximum)
        {
            int num = 0;
            while ((num = NextInt32(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region UInt32
        /// <summary>
        /// Get a random unsigned 32bit integer
        /// </summary>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt32 NextUInt32()
        {
            return BitConverter.ToUInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random unsigned integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt32 NextUInt32(UInt32 Maximum)
        {
            byte[] rand;
            UInt32[] num = new UInt32[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a random unsigned integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt32 NextUInt32(UInt32 Minimum, UInt32 Maximum)
        {
            UInt32 num = 0;
            while ((num = NextUInt32(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region Int64
        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextInt64()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextInt64(Int64 Maximum)
        {
            byte[] rand;
            Int64[] num = new Int64[1];

            do
            {
                rand = GetByteRange((Int64)Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1)
                num[0] = 0;

            return num[0];
        }

        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextInt64(Int64 Minimum, Int64 Maximum)
        {
            Int64 num = 0;
            while ((num = NextInt64(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region UInt64
        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <returns>Random UInt64</returns>
        [CLSCompliant(false)]
        public UInt64 NextUInt64()
        {
            return BitConverter.ToUInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt64</returns>
        [CLSCompliant(false)]
        public UInt64 NextUInt64(UInt64 Maximum)
        {
            byte[] rand = GetByteRange((Int64)Maximum);
            UInt64[] num = new UInt64[1];

            do
            {
                rand = GetByteRange((Int64)Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt64</returns>
        [CLSCompliant(false)]
        public UInt64 NextUInt64(UInt64 Minimum, UInt64 Maximum)
        {
            UInt64 num = 0;
            while ((num = NextUInt64(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region Array Generators
        /// <summary>
        /// Gets bytes of pseudo random
        /// </summary>
        /// 
        /// <param name="Size">Size of request</param>
        /// 
        /// <returns>P-Rand bytes</returns>
        public byte[] GetBytes(int Size)
        {
            lock (_objLock)
            {
                byte[] data = new byte[Size];
                if (_byteBuffer.Length - _bufferIndex < data.Length)
                {
                    int bufSize = _byteBuffer.Length - _bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, data, 0, bufSize);
                    int rem = Size - bufSize;

                    while (rem > 0)
                    {
                        _rngEngine.GetBytes(_byteBuffer);
                        if (rem > _byteBuffer.Length)
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, data, bufSize, _byteBuffer.Length);
                            bufSize += _byteBuffer.Length;
                            rem -= _byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, data, bufSize, rem);
                            _bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, data, 0, data.Length);
                    _bufferIndex += data.Length;
                }

                return data;
            }
        }

        /// <summary>
        /// Gets bytes of pseudo random
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with pseudo random</param>
        public void GetBytes(byte[] Data)
        {
            lock (_objLock)
            {
                if (_byteBuffer.Length - _bufferIndex < Data.Length)
                {
                    int bufSize = _byteBuffer.Length - _bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, Data, 0, bufSize);
                    int rem = Data.Length - bufSize;

                    while (rem > 0)
                    {
                        _rngEngine.GetBytes(_byteBuffer);
                        if (rem > _byteBuffer.Length)
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, Data, bufSize, _byteBuffer.Length);
                            bufSize += _byteBuffer.Length;
                            rem -= _byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, Data, bufSize, rem);
                            _bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, Data, 0, Data.Length);
                    _bufferIndex += Data.Length;
                }
            }
        }

        /// <summary>
        /// Gets pseudo random chars
        /// </summary>
        /// 
        /// <param name="Size">Size of request</param>
        /// 
        /// <returns>P-Rand chars</returns>
        public char[] GetChars(int Size)
        {
            char[] data = new char[Size];
            Buffer.BlockCopy(GetBytes(Size * 2), 0, data, 0, Size);
            return data;
        }
        #endregion

        #region Private Methods
        /// <remarks>
        /// Returns the number of bytes needed to build 
        /// an integer existing within a byte range
        /// </remarks>
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

        /// <remarks>
        /// If you need a dice roll, use the Random class (smaller range = reduced entropy)
        /// </remarks>
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
                try
                {
                    if (_rngEngine != null)
                    {
                        _rngEngine.Dispose();
                        _rngEngine = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
