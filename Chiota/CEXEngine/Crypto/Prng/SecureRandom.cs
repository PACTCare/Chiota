#region Directives
using System;
using System.Security.Cryptography;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// An implementation of a Cryptographically Secure Pseudo Random Number Generator (SecureRandom). 
// Uses the <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a> class to produce pseudo random output.
// Written by John Underhill, January 6, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// SecureRandom: An implementation of a Cryptographically Secure Pseudo Random Number Generator: SecureRandom. 
    /// 
    /// <para>Uses the <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a>: class to generate non-negative random numbers.</para>
    /// </summary>
    /// 
    /// <example>
    /// <c>
    /// int x;
    /// using (SecureRandom rnd = new SecureRandom())
    ///     x = rnd.NextInt32();
    /// </c>
    /// </example>
    public sealed class SecureRandom : IDisposable
    {
        #region Constants
        private const UInt16 MAXD16 = 16368;
        private const int BUFFER_SIZE = 1024;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private RNGCryptoServiceProvider m_rngEngine;
        private byte[] m_byteBuffer;
        private int m_bufferIndex = 0;
        private int m_bufferSize = 0;
        private object m_objLock = new object();
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

            m_byteBuffer = new byte[BufferSize];
            m_bufferSize = BufferSize;
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
        /// Reset the SecureRandom instance
        /// </summary>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if RNGCryptoServiceProvider initialization failed</exception>
        public void Reset()
        {
            lock (m_objLock)
            {
                if (m_rngEngine != null)
                {
                    m_rngEngine.Dispose();
                    m_rngEngine = null;
                }

                try
                {
                    m_rngEngine = new RNGCryptoServiceProvider();
                }
                catch (Exception ex)
                {
                    if (m_rngEngine == null)
                        throw new CryptoRandomException("SecureRandom:Reset", "RNGCrypto could not be initialized!", ex);
                }

                m_rngEngine.GetBytes(m_byteBuffer);
                m_bufferIndex = 0;
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
        /// <returns>Random uint</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16(UInt16 Minimum, UInt16 Maximum)
        {
            UInt16 num = 0;
            while ((num = NextUInt16(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region int
        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
        public int Next()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
        public int NextInt32()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random int</returns>
        public int NextInt32(int Maximum)
        {
            byte[] rand;
            int[] num = new int[1];

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
        /// <returns>Random int</returns>
        public int NextInt32(int Minimum, int Maximum)
        {
            int num = 0;
            while ((num = NextInt32(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region uint
        /// <summary>
        /// Get a random unsigned 32bit integer
        /// </summary>
        /// 
        /// <returns>Random uint</returns>
        [CLSCompliant(false)]
        public uint NextUInt32()
        {
            return BitConverter.ToUInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random unsigned integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random uint</returns>
        [CLSCompliant(false)]
        public uint NextUInt32(uint Maximum)
        {
            byte[] rand;
            uint[] num = new uint[1];

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
        /// <returns>Random uint</returns>
        [CLSCompliant(false)]
        public uint NextUInt32(uint Minimum, uint Maximum)
        {
            uint num = 0;
            while ((num = NextUInt32(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region long
        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <returns>Random long</returns>
        public long NextInt64()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        public long NextInt64(long Maximum)
        {
            byte[] rand;
            long[] num = new long[1];

            do
            {
                rand = GetByteRange((long)Maximum);
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
        /// <returns>Random long</returns>
        public long NextInt64(long Minimum, long Maximum)
        {
            long num = 0;
            while ((num = NextInt64(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region ulong
        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <returns>Random ulong</returns>
        [CLSCompliant(false)]
        public ulong NextUInt64()
        {
            return BitConverter.ToUInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random ulong</returns>
        [CLSCompliant(false)]
        public ulong NextUInt64(ulong Maximum)
        {
            byte[] rand = GetByteRange((long)Maximum);
            ulong[] num = new ulong[1];

            do
            {
                rand = GetByteRange((long)Maximum);
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
        /// <returns>Random ulong</returns>
        [CLSCompliant(false)]
        public ulong NextUInt64(ulong Minimum, ulong Maximum)
        {
            ulong num = 0;
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
            lock (m_objLock)
            {
                byte[] data = new byte[Size];
                if (m_byteBuffer.Length - m_bufferIndex < data.Length)
                {
                    int bufSize = m_byteBuffer.Length - m_bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, data, 0, bufSize);
                    int rem = Size - bufSize;

                    while (rem > 0)
                    {
                        m_rngEngine.GetBytes(m_byteBuffer);
                        if (rem > m_byteBuffer.Length)
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, data, bufSize, m_byteBuffer.Length);
                            bufSize += m_byteBuffer.Length;
                            rem -= m_byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, data, bufSize, rem);
                            m_bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, data, 0, data.Length);
                    m_bufferIndex += data.Length;
                }

                return data;
            }
        }

        /// <summary>
        /// Gets bytes of pseudo random
        /// </summary>
        /// 
        /// <param name="Output">Array to fill with pseudo random</param>
        public void GetBytes(byte[] Output)
        {
            lock (m_objLock)
            {
                if (m_byteBuffer.Length - m_bufferIndex < Output.Length)
                {
                    int bufSize = m_byteBuffer.Length - m_bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, Output, 0, bufSize);
                    int rem = Output.Length - bufSize;

                    while (rem > 0)
                    {
                        m_rngEngine.GetBytes(m_byteBuffer);
                        if (rem > m_byteBuffer.Length)
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, Output, bufSize, m_byteBuffer.Length);
                            bufSize += m_byteBuffer.Length;
                            rem -= m_byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, Output, bufSize, rem);
                            m_bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, Output, 0, Output.Length);
                    m_bufferIndex += Output.Length;
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

        /// <remarks>
        /// If you need a dice roll, use the Random class (smaller range = reduced entropy)
        /// </remarks>
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
                    if (m_rngEngine != null)
                    {
                        m_rngEngine.Dispose();
                        m_rngEngine = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
