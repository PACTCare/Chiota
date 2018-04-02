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
// An implementation of the SHA3 digest finalist, Blake, designed by Jean-Philippe Aumasson, Luca Henzen, Willi Meier, and Raphael C.-W. Phan. 
// SHA3 Proposal <see href="https://131002.net/blake/blake.pdf">Blake</see>.
// 
// Implementation Details:
// An implementation of the Blake digest with a 512 bit digest size.
// Written by John Underhill, January 12, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// <h3>Blake512: An implementation of the Blake digest with a 512 bit return size.</h3>
    /// <para>SHA-3 finalist<cite>NIST IR7896</cite>: The Blake<cite>Blake</cite> digest</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new Blake512())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
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
    /// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>SHA3 Proposal <see href="https://131002.net/blake">Blake</see>.</description></item>
    /// <item><description>SHA3: <see href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</description></item>
    /// <item><description>SHA3 Submission in C: <see href="https://131002.net/blake/blake_ref.c">blake_ref.c</see>.</description></item>
    /// <item><description>The: <see href="http://hashlib.codeplex.com/">HashLib</see> Project (test vectors).</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent project by Dominik Reichl: <see href="http://www.codeproject.com/Articles/286937/BlakeSharp-A-Csharp-Implementation-of-the-BLAKE-Ha">Blake Sharp</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Blake512 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "Blake512";
        private const int BLOCK_SIZE = 64;
        private const int DIGEST_SIZE = 64;
        private const int PAD_LENGTH = 111;
        private const int ROUNDS = 16;
        private const UInt64 TN_888 = 888;
        private const UInt64 TN_1024 = 1024;
        #endregion

        #region Fields
        private int _dataLen = 0;
        private byte[] _digestState = new byte[128];
        private UInt64[] _hashVal = new UInt64[8];
        private bool _isDisposed = false;
        private bool _isNullT;
        private UInt64[] _salt64 = new UInt64[4];
        private UInt64[] _M = new UInt64[16];
        private UInt64 _T;
        private UInt64[] _V = new UInt64[16];

        private static readonly UInt64[] _C64 = new UInt64[16] 
        {
			0x243F6A8885A308D3UL, 0x13198A2E03707344UL, 0xA4093822299F31D0UL, 0x082EFA98EC4E6C89UL, 
            0x452821E638D01377UL, 0xBE5466CF34E90C6CUL, 0xC0AC29B7C97C50DDUL, 0x3F84D5B5B5470917UL, 
            0x9216D5D98979FB1BUL, 0xD1310BA698DFB5ACUL, 0x2FFD72DBD01ADFB7UL, 0xB8E1AFED6A267E96UL,
			0xBA7C9045F12C7F99UL, 0x24A19947B3916CF7UL, 0x0801F2E2858EFC16UL, 0x636920D871574E69UL
		};

        private static Int32[] _ftSigma;

        private static readonly byte[] _Padding = new byte[128] 
        {
			0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		};
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
        /// Get: The Digest name
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
        public Blake512()
        {
            Initialize();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Blake512()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the buffer
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
                throw new CryptoHashException("Blake512:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            int offset = InOffset;
            int fill = 128 - _dataLen;

            // compress remaining data filled with new bits
            if ((_dataLen > 0) && (Length >= fill))
            {
                Buffer.BlockCopy(Input, offset, _digestState, _dataLen, fill);
                _T += TN_1024;
                Compress64(_digestState, 0);
                offset += fill;
                Length -= fill;
                _dataLen = 0;
            }

            // compress data until enough for a block
            while (Length >= 128)
            {
                _T += TN_1024;
                Compress64(Input, offset);
                offset += 128;
                Length -= 128;
            }

            if (Length > 0)
            {
                Buffer.BlockCopy(Input, offset, _digestState, _dataLen, Length);
                _dataLen += Length;
            }
            else
            {
                _dataLen = 0;
            }
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value</returns>
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
        /// <returns>Size of Hash value</returns>
        /// 
        /// <exception cref="CryptoHashException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < DigestSize)
                throw new CryptoHashException("Blake512:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            byte[] msgLen = new byte[16];

            UInt64ToBytes(_T + ((UInt64)_dataLen << 3), msgLen, 8);

            // special case of one padding byte
            if (_dataLen == PAD_LENGTH)
            {
                _T -= 8;
                BlockUpdate(new byte[1] { 0x81 }, 0, 1);
            }
            else
            {
                if (_dataLen < PAD_LENGTH)
                {
                    // enough space to fill the block
                    if (_dataLen == 0) 
                        _isNullT = true;

                    _T -= TN_888 - ((UInt64)_dataLen << 3);
                    BlockUpdate(_Padding, 0, PAD_LENGTH - _dataLen);
                }
                else
                {
                    // not enough space, need 2 compressions 
                    _T -= TN_1024 - ((UInt64)_dataLen << 3);
                    BlockUpdate(_Padding, 0, 128 - _dataLen);

                    _T -= TN_888;
                    BlockUpdate(_Padding, 1, PAD_LENGTH);

                    _isNullT = true;
                }

                BlockUpdate(new byte[1] { 0x01 }, 0, 1);
                _T -= 8;
            }

            _T -= 128;
            BlockUpdate(msgLen, 0, 16);

            byte[] digest = new byte[64];

            for (int i = 0; i < 8; ++i)
                UInt64ToBytes(_hashVal[i], digest, i << 3);

            Buffer.BlockCopy(digest, 0, Output, OutOffset, digest.Length);

            Reset();

            return Output.Length;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            Initialize();
        }

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            BlockUpdate(new byte[] { Input }, 0, 1);
        }
        #endregion

        #region Private Methods
        private static UInt64 BytesToUInt64(byte[] Input, int InOffset)
        {
            return ((UInt64)Input[InOffset + 7] | 
                ((UInt64)Input[InOffset + 6] << 8) |
                ((UInt64)Input[InOffset + 5] << 16) | 
                ((UInt64)Input[InOffset + 4] << 24) |
                ((UInt64)Input[InOffset + 3] << 32) | 
                ((UInt64)Input[InOffset + 2] << 40) |
                ((UInt64)Input[InOffset + 1] << 48) | 
                ((UInt64)Input[InOffset] << 56));
        }

        private void Compress64(byte[] pbBlock, int iOffset)
        {
            for (int i = 0; i < 16; ++i)
                _M[i] = BytesToUInt64(pbBlock, iOffset + (i << 3));

            Array.Copy(_hashVal, _V, 8);

            _V[8] = _salt64[0] ^ 0x243F6A8885A308D3UL;
            _V[9] = _salt64[1] ^ 0x13198A2E03707344UL;
            _V[10] = _salt64[2] ^ 0xA4093822299F31D0UL;
            _V[11] = _salt64[3] ^ 0x082EFA98EC4E6C89UL;
            _V[12] = 0x452821E638D01377UL;
            _V[13] = 0xBE5466CF34E90C6CUL;
            _V[14] = 0xC0AC29B7C97C50DDUL;
            _V[15] = 0x3F84D5B5B5470917UL;

            if (!_isNullT)
            {
                _V[12] ^= _T;
                _V[13] ^= _T;
            }

            //  do 16 rounds
            for (int cnt = 0; cnt < ROUNDS; ++cnt)
            {
                G64(0, 4, 8, 12, cnt, 0);
                G64(1, 5, 9, 13, cnt, 2);
                G64(2, 6, 10, 14, cnt, 4);
                G64(3, 7, 11, 15, cnt, 6);
                G64(3, 4, 9, 14, cnt, 14);
                G64(2, 7, 8, 13, cnt, 12);
                G64(0, 5, 10, 15, cnt, 8);
                G64(1, 6, 11, 12, cnt, 10);
            }

            // finalization
            for (int i = 0; i < 8; ++i) 
                _hashVal[i] ^= _V[i];
            for (int i = 0; i < 8; ++i) 
                _hashVal[i] ^= _V[i + 8];
            for (int i = 0; i < 4; ++i) 
                _hashVal[i] ^= _salt64[i];
            for (int i = 0; i < 4; ++i)
                _hashVal[i + 4] ^= _salt64[i];
        }

        private void G64(int A, int B, int C, int D, int R, int I)
        {
            int P = (R << 4) + I;
            int P0 = _ftSigma[P];
            int P1 = _ftSigma[P + 1];

            // initialization
            _V[A] += _V[B] + (_M[P0] ^ _C64[P1]);
            _V[D] = RotateRight(_V[D] ^ _V[A], 32);
            _V[C] += _V[D];
            _V[B] = RotateRight(_V[B] ^ _V[C], 25);
            _V[A] += _V[B] + (_M[P1] ^ _C64[P0]);
            _V[D] = RotateRight(_V[D] ^ _V[A], 16);
            _V[C] += _V[D];
            _V[B] = RotateRight(_V[B] ^ _V[C], 11);
        }

        private void Initialize()
        {
            _hashVal = new UInt64[] 
            { 
                0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL, 
                0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
            };

            _ftSigma = new int[ROUNDS * 16] 
            {
			    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
			    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
			    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
			    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
			    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
			    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
			    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
			    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
			    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
			    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
			    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
			    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
			    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
			    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9
		    };

            Array.Clear(_salt64, 0, _salt64.Length);

            _T = 0;
            _dataLen = 0;
            _isNullT = false;

            Array.Clear(_digestState, 0, _digestState.Length);
        }

        private static UInt64 RotateRight(UInt64 Input, int Bits)
        {
            return ((Input >> Bits) | (Input << (64 - Bits)));
        }

        private static void UInt64ToBytes(UInt64 Input, byte[] Output, int OutOffset)
        {
            for (int i = 7; i >= 0; --i)
            {
                Output[OutOffset + i] = (byte)(Input & 0xFF);
                Input >>= 8;
            }
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
                    if (_hashVal != null)
                    {
                        Array.Clear(_hashVal, 0, _hashVal.Length);
                        _hashVal = null;
                    }
                    if (_M != null)
                    {
                        Array.Clear(_M, 0, _M.Length);
                        _M = null;
                    }
                    if (_salt64 != null)
                    {
                        Array.Clear(_salt64, 0, _salt64.Length);
                        _salt64 = null;
                    }
                    if (_digestState != null)
                    {
                        Array.Clear(_digestState, 0, _digestState.Length);
                        _digestState = null;
                    }
                    if (_V != null)
                    {
                        Array.Clear(_V, 0, _V.Length);
                        _V = null;
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
