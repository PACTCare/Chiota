#region Directives
using System;
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
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 256 bit return size.
// SHA-2 <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 256 bit return size. 
// Refactoring, a couple of small optimizations, Dispose, and a ComputeHash method added.
// Many thanks to the authors of BouncyCastle for their great contributions.
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// <h3>SHA256: An implementation of the SHA-2 digest with a 256 bit digest return size</h3>.
    /// <para>The SHA-2<cite>Fips 180-4</cite> 256 digest</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new SHA256())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/11" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Changes to formatting and documentation</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Block size is 64 bytes, (512 bits).</description></item>
    /// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>SHA-2 <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SHA256 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "SHA256";
        private Int32 BLOCK_SIZE = 64;
        private Int32 DIGEST_SIZE = 32;
        #endregion

        #region Fields
        private Int32 _bufferOffset = 0;
        private Int64 _byteCount = 0;
        private byte[] _processBuffer = new byte[4];
        private UInt32 _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7;
        private bool _isDisposed = false;
        private UInt32[] _wordBuffer = new UInt32[64];
        private Int32 _wordOffset = 0;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// Get: Digest name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the digest
        /// </summary>
        public SHA256()
        {
            Initialize();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SHA256()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the SHA256 buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoHashException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoHashException("SHA256:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            // fill the current word
            while ((_bufferOffset != 0) && (Length > 0))
            {
                Update(Input[InOffset]);
                InOffset++;
                Length--;
            }

            // process whole words
            while (Length > _processBuffer.Length)
            {
                ProcessWord(Input, InOffset);

                InOffset += _processBuffer.Length;
                Length -= _processBuffer.Length;
                _byteCount += _processBuffer.Length;
            }

            // load in the remainder
            while (Length > 0)
            {
                Update(Input[InOffset]);

                InOffset++;
                Length--;
            }
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value [32 bytes]</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            byte[] hash = new byte[DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Do final processing and get the hash value
        /// </summary>
        /// 
        /// <param name="Output">The Hash value container</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value, Always 32 bytes</returns>
        /// 
        /// <exception cref="CryptoHashException">Thrown if Output array is too small</exception>
        public Int32 DoFinal(byte[] Output, Int32 OutOffset)
        {
            if (Output.Length - OutOffset < DigestSize)
                throw new CryptoHashException("SHA256:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            Finish();

            UInt32ToBE((UInt32)_H0, Output, OutOffset);
            UInt32ToBE((UInt32)_H1, Output, OutOffset + 4);
            UInt32ToBE((UInt32)_H2, Output, OutOffset + 8);
            UInt32ToBE((UInt32)_H3, Output, OutOffset + 12);
            UInt32ToBE((UInt32)_H4, Output, OutOffset + 16);
            UInt32ToBE((UInt32)_H5, Output, OutOffset + 20);
            UInt32ToBE((UInt32)_H6, Output, OutOffset + 24);
            UInt32ToBE((UInt32)_H7, Output, OutOffset + 28);

            Reset();

            return DIGEST_SIZE;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _byteCount = 0;
            _bufferOffset = 0;
            Array.Clear(_processBuffer, 0, _processBuffer.Length);

            Initialize();
        }

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _processBuffer[_bufferOffset++] = Input;

            if (_bufferOffset == _processBuffer.Length)
            {
                ProcessWord(_processBuffer, 0);
                _bufferOffset = 0;
            }

            _byteCount++;
        }
        #endregion

        #region Private Methods
        private void Finish()
        {
            Int64 bitLength = (_byteCount << 3);

            Update((byte)128);

            while (_bufferOffset != 0)
                Update((byte)0);

            ProcessLength(bitLength);
            ProcessBlock();
        }

        private void Initialize()
        {
            // The first 32 bits of the fractional parts of the square roots of the first eight prime numbers
            _H0 = 0x6a09e667;
            _H1 = 0xbb67ae85;
            _H2 = 0x3c6ef372;
            _H3 = 0xa54ff53a;
            _H4 = 0x510e527f;
            _H5 = 0x9b05688c;
            _H6 = 0x1f83d9ab;
            _H7 = 0x5be0cd19;
        }

        private void ProcessBlock()
        {
            Int32 ctr = 0;
            UInt32 w0 = _H0;
            UInt32 w1 = _H1;
            UInt32 w2 = _H2;
            UInt32 w3 = _H3;
            UInt32 w4 = _H4;
            UInt32 w5 = _H5;
            UInt32 w6 = _H6;
            UInt32 w7 = _H7;

            // expand 16 word block into 64 word blocks
            for (int i = 16; i < 64; i++)
                _wordBuffer[i] = Theta1(_wordBuffer[i - 2]) + _wordBuffer[i - 7] + Theta0(_wordBuffer[i - 15]) + _wordBuffer[i - 16];

            for (int i = 0; i < 8; ++i)
            {
                // t = 8 * i
                w7 += Sum1Ch(w4, w5, w6) + K1C[ctr] + _wordBuffer[ctr];
                w3 += w7;
                w7 += Sum0Maj(w0, w1, w2);
                ++ctr;
                // t = 8 * i + 1
                w6 += Sum1Ch(w3, w4, w5) + K1C[ctr] + _wordBuffer[ctr];
                w2 += w6;
                w6 += Sum0Maj(w7, w0, w1);
                ++ctr;
                // t = 8 * i + 2
                w5 += Sum1Ch(w2, w3, w4) + K1C[ctr] + _wordBuffer[ctr];
                w1 += w5;
                w5 += Sum0Maj(w6, w7, w0);
                ++ctr;
                // t = 8 * i + 3
                w4 += Sum1Ch(w1, w2, w3) + K1C[ctr] + _wordBuffer[ctr];
                w0 += w4;
                w4 += Sum0Maj(w5, w6, w7);
                ++ctr;
                // t = 8 * i + 4
                w3 += Sum1Ch(w0, w1, w2) + K1C[ctr] + _wordBuffer[ctr];
                w7 += w3;
                w3 += Sum0Maj(w4, w5, w6);
                ++ctr;
                // t = 8 * i + 5
                w2 += Sum1Ch(w7, w0, w1) + K1C[ctr] + _wordBuffer[ctr];
                w6 += w2;
                w2 += Sum0Maj(w3, w4, w5);
                ++ctr;
                // t = 8 * i + 6
                w1 += Sum1Ch(w6, w7, w0) + K1C[ctr] + _wordBuffer[ctr];
                w5 += w1;
                w1 += Sum0Maj(w2, w3, w4);
                ++ctr;
                // t = 8 * i + 7
                w0 += Sum1Ch(w5, w6, w7) + K1C[ctr] + _wordBuffer[ctr];
                w4 += w0;
                w0 += Sum0Maj(w1, w2, w3);
                ++ctr;
            }

            _H0 += w0;
            _H1 += w1;
            _H2 += w2;
            _H3 += w3;
            _H4 += w4;
            _H5 += w5;
            _H6 += w6;
            _H7 += w7;

            // reset the offset and clear the word buffer
            _wordOffset = 0;
            Array.Clear(_wordBuffer, 0, 16);
        }

        private void ProcessLength(long BitLength)
        {
            if (_wordOffset > 14)
                ProcessBlock();

            _wordBuffer[14] = (UInt32)((UInt64)BitLength >> 32);
            _wordBuffer[15] = (UInt32)((UInt64)BitLength);
        }

        private void ProcessWord(byte[] Input, int Offset)
        {
            _wordBuffer[_wordOffset] = BEToUInt32(Input, Offset);

            if (++_wordOffset == 16)
                ProcessBlock();
        }
        #endregion

        #region Helpers
        /// <remarks>
        /// Big Endian to UInt32
        /// </remarks>
        private static UInt32 BEToUInt32(byte[] Input, int InOffset)
        {
            UInt32 n = (UInt32)Input[InOffset] << 24;
            n |= (UInt32)Input[++InOffset] << 16;
            n |= (UInt32)Input[++InOffset] << 8;
            n |= (UInt32)Input[++InOffset];
            return n;
        }

        /// <remarks>
        /// UInt32 to Big Endian
        /// </remarks>
        private static void UInt32ToBE(UInt32 Input, byte[] Output, int OutOffset)
        {
            Output[OutOffset] = (byte)(Input >> 24);
            Output[++OutOffset] = (byte)(Input >> 16);
            Output[++OutOffset] = (byte)(Input >> 8);
            Output[++OutOffset] = (byte)(Input);
        }

        private static UInt32 Sum1Ch(UInt32 X, UInt32 Y, UInt32 Z)
        {
            return (((X >> 6) | (X << 26)) ^ ((X >> 11) | (X << 21)) ^ ((X >> 25) | (X << 7))) + ((X & Y) ^ ((~X) & Z));
        }

        private static UInt32 Sum0Maj(UInt32 X, UInt32 Y, UInt32 Z)
        {
            return (((X >> 2) | (X << 30)) ^ ((X >> 13) | (X << 19)) ^ ((X >> 22) | (X << 10))) + ((X & Y) ^ (X & Z) ^ (Y & Z));
        }

        private static UInt32 Theta0(UInt32 X)
        {
            return ((X >> 7) | (X << 25)) ^ ((X >> 18) | (X << 14)) ^ (X >> 3);
        }

        private static UInt32 Theta1(UInt32 X)
        {
            return ((X >> 17) | (X << 15)) ^ ((X >> 19) | (X << 13)) ^ (X >> 10);
        }
        #endregion

        #region Constant Tables
        /// <remarks>
        /// the first 32 bits of the fractional parts of the cube roots of the first sixty-four prime numbers)
        /// </remarks>
        private static readonly UInt32[] K1C = { 
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
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
                    if (_processBuffer != null)
                    {
                        Array.Clear(_processBuffer, 0, _processBuffer.Length);
                        _processBuffer = null;
                    }
                    if (_wordBuffer != null)
                    {
                        Array.Clear(_wordBuffer, 0, _wordBuffer.Length);
                        _wordBuffer = null;
                    }
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
