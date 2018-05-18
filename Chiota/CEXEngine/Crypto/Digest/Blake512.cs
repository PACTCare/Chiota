#region Directives
using System;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Utility;
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
// Principal Algorithms:
// An implementation of the SHA3 digest finalist, Blake, designed by Jean-Philippe Aumasson, Luca Henzen, Willi Meier, and Raphael C.-W. Phan. 
// SHA3 Proposal <a href="https://131002.net/blake/blake.pdf">Blake</a>.
// 
// Implementation Details:
// An implementation of the Blake digest with a 512 bit digest size.
// Written by John Underhill, January 12, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// Blake512: An implementation of the Blake digest with a 512 bit return size
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Block size is 128 bytes, (1024 bits).</description></item>
    /// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
    /// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
    /// <item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent project by Dominik Reichl: <a href="http://www.codeproject.com/Articles/286937/BlakeSharp-A-Csharp-Implementation-of-the-BLAKE-Ha">Blake Sharp</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Blake512 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "Blake512";
        private const int BLOCK_SIZE = 128;
        private const int DIGEST_SIZE = 64;
        private const int PAD_LENGTH = 111;
        private const int ROUNDS = 16;
        private const ulong TN_888 = 888;
        private const ulong TN_1024 = 1024;
        #endregion

        #region Fields
        private int _dataLen = 0;
        private byte[] _msgState = new byte[128];
        private ulong[] _hashVal = new ulong[8];
        private bool m_isDisposed = false;
        private bool _isNullT;
        private ulong[] _salt64 = new ulong[4];
        private ulong[] _M = new ulong[16];
        private ulong _T;
        private ulong[] _V = new ulong[16];

        private static readonly ulong[] _C64 = new ulong[16] 
        {
			0x243F6A8885A308D3UL, 0x13198A2E03707344UL, 0xA4093822299F31D0UL, 0x082EFA98EC4E6C89UL, 
            0x452821E638D01377UL, 0xBE5466CF34E90C6CUL, 0xC0AC29B7C97C50DDUL, 0x3F84D5B5B5470917UL, 
            0x9216D5D98979FB1BUL, 0xD1310BA698DFB5ACUL, 0x2FFD72DBD01ADFB7UL, 0xB8E1AFED6A267E96UL,
			0xBA7C9045F12C7F99UL, 0x24A19947B3916CF7UL, 0x0801F2E2858EFC16UL, 0x636920D871574E69UL
		};

        private static uint[] _ftSigma;

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
        /// Get: The digests type name
        /// </summary>
        public Digests Enumeral
        {
            get { return Digests.Blake512; }
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
        /// Initialize the class with a salt value
        /// </summary>
        /// 
        /// <param name="Salt">The optional salt value; must be 4 ulong in length</param>
        public Blake512(long[] Salt)
        {
            if (Salt.Length != 4)
                throw new CryptoHashException("Blake512:Ctor", "The Salt array length must be 4!", new ArgumentOutOfRangeException());

            Array.Copy(Salt, _salt64, _salt64.Length);
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
                Buffer.BlockCopy(Input, offset, _msgState, _dataLen, fill);
                _T += TN_1024;
                Compress(_msgState, 0);
                offset += fill;
                Length -= fill;
                _dataLen = 0;
            }

            // compress data until enough for a block
            while (Length >= 128)
            {
                _T += TN_1024;
                Compress(Input, offset);
                offset += 128;
                Length -= 128;
            }

            if (Length > 0)
            {
                Buffer.BlockCopy(Input, offset, _msgState, _dataLen, Length);
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

            IntUtils.Be64ToBytes(_T + ((ulong)_dataLen << 3), msgLen, 8);

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

                    _T -= TN_888 - ((ulong)_dataLen << 3);
                    BlockUpdate(_Padding, 0, PAD_LENGTH - _dataLen);
                }
                else
                {
                    // not enough space, need 2 compressions 
                    _T -= TN_1024 - ((ulong)_dataLen << 3);
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

            IntUtils.Be64ToBytes(_hashVal[0], digest, 0);
            IntUtils.Be64ToBytes(_hashVal[1], digest, 8);
            IntUtils.Be64ToBytes(_hashVal[2], digest, 16);
            IntUtils.Be64ToBytes(_hashVal[3], digest, 24);
            IntUtils.Be64ToBytes(_hashVal[4], digest, 32);
            IntUtils.Be64ToBytes(_hashVal[5], digest, 40);
            IntUtils.Be64ToBytes(_hashVal[6], digest, 48);
            IntUtils.Be64ToBytes(_hashVal[7], digest, 56);

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
        private void Compress(byte[] Block, int Offset)
        {
            _M[0] = IntUtils.BytesToBe64(Block, Offset);
            _M[1] = IntUtils.BytesToBe64(Block, Offset + 8);
            _M[2] = IntUtils.BytesToBe64(Block, Offset + 16);
            _M[3] = IntUtils.BytesToBe64(Block, Offset + 24);
            _M[4] = IntUtils.BytesToBe64(Block, Offset + 32);
            _M[5] = IntUtils.BytesToBe64(Block, Offset + 40);
            _M[6] = IntUtils.BytesToBe64(Block, Offset + 48);
            _M[7] = IntUtils.BytesToBe64(Block, Offset + 56);
            _M[8] = IntUtils.BytesToBe64(Block, Offset + 64);
            _M[9] = IntUtils.BytesToBe64(Block, Offset + 72);
            _M[10] = IntUtils.BytesToBe64(Block, Offset + 80);
            _M[11] = IntUtils.BytesToBe64(Block, Offset + 88);
            _M[12] = IntUtils.BytesToBe64(Block, Offset + 96);
            _M[13] = IntUtils.BytesToBe64(Block, Offset + 104);
            _M[14] = IntUtils.BytesToBe64(Block, Offset + 112);
            _M[15] = IntUtils.BytesToBe64(Block, Offset + 120);

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
            uint index = 0;
            do
            {
                MixBlock(index);
                index++;

            } while (index != ROUNDS);

            // finalization
            _hashVal[0] ^= _V[0];
            _hashVal[1] ^= _V[1];
            _hashVal[2] ^= _V[2];
            _hashVal[3] ^= _V[3];
            _hashVal[4] ^= _V[4];
            _hashVal[5] ^= _V[5];
            _hashVal[6] ^= _V[6];
            _hashVal[7] ^= _V[7];
            _hashVal[0] ^= _V[8];
            _hashVal[1] ^= _V[9];
            _hashVal[2] ^= _V[10];
            _hashVal[3] ^= _V[11];
            _hashVal[4] ^= _V[12];
            _hashVal[5] ^= _V[13];
            _hashVal[6] ^= _V[14];
            _hashVal[7] ^= _V[15];
            _hashVal[0] ^= _salt64[0];
            _hashVal[1] ^= _salt64[1];
            _hashVal[2] ^= _salt64[2];
            _hashVal[3] ^= _salt64[3];
            _hashVal[4] ^= _salt64[0];
            _hashVal[5] ^= _salt64[1];
            _hashVal[6] ^= _salt64[2];
            _hashVal[7] ^= _salt64[3];
        }

        private void Initialize()
        {
            _hashVal = new ulong[] 
            { 
                0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL, 
                0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
            };

            _ftSigma = new uint[ROUNDS * 16] 
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

            Array.Clear(_msgState, 0, _msgState.Length);
        }

        private void Mix(uint A, uint B, uint C, uint D, uint R, uint I)
        {
            uint P = (R << 4) + I;
            uint P0 = _ftSigma[P];
            uint P1 = _ftSigma[P + 1];

            // initialization
            _V[A] += _V[B] + (_M[P0] ^ _C64[P1]);
            _V[D] = IntUtils.RotateRight(_V[D] ^ _V[A], 32);
            _V[C] += _V[D];
            _V[B] = IntUtils.RotateRight(_V[B] ^ _V[C], 25);
            _V[A] += _V[B] + (_M[P1] ^ _C64[P0]);
            _V[D] = IntUtils.RotateRight(_V[D] ^ _V[A], 16);
            _V[C] += _V[D];
            _V[B] = IntUtils.RotateRight(_V[B] ^ _V[C], 11);
        }

        void MixBlock(uint Index)
        {
            Mix(0, 4, 8, 12, Index, 0);
            Mix(1, 5, 9, 13, Index, 2);
            Mix(2, 6, 10, 14, Index, 4);
            Mix(3, 7, 11, 15, Index, 6);
            Mix(3, 4, 9, 14, Index, 14);
            Mix(2, 7, 8, 13, Index, 12);
            Mix(0, 5, 10, 15, Index, 8);
            Mix(1, 6, 11, 12, Index, 10);
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
                    if (_msgState != null)
                    {
                        Array.Clear(_msgState, 0, _msgState.Length);
                        _msgState = null;
                    }
                    if (_V != null)
                    {
                        Array.Clear(_V, 0, _V.Length);
                        _V = null;
                    }
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
