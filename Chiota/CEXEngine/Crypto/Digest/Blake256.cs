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
// An implementation of the Blake digest with a 256 bit digest size.
// Written by John Underhill, January 12, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// Blake256: An implementation of the Blake digest with a 256 bit return size
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new Blake256())
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
    /// <item><description>Block size is 64 bytes, (512 bits).</description></item>
    /// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
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
    public sealed class Blake256 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "Blake256";
        private const int BLOCK_SIZE = 64;
        private const int DIGEST_SIZE = 32;
        private const int PAD_LENGTH = 55;
        private const int ROUNDS = 14;
        private const ulong TN_440 = 440;
        private const ulong TN_512 = 512;
        #endregion

        #region Fields
        private int _dataLen = 0;
        private uint[] _hashVal = new uint[8];
        private bool m_isDisposed = false;
        private bool _isNullT;
        private uint[] _salt32 = new uint[4];
        private static uint[] _ftSigma;
        private byte[] _msgState = new byte[64];
        private uint[] _M = new uint[16];
        private ulong _T;
        private uint[] _V = new uint[16];

        private static readonly uint[] _C32 = new uint[16] 
        {
			0x243F6A88U, 0x85A308D3U, 0x13198A2EU, 0x03707344U,
			0xA4093822U, 0x299F31D0U, 0x082EFA98U, 0xEC4E6C89U,
			0x452821E6U, 0x38D01377U, 0xBE5466CFU, 0x34E90C6CU,
			0xC0AC29B7U, 0xC97C50DDU, 0x3F84D5B5U, 0xB5470917U
		};

        private static readonly byte[] _Padding = new byte[64] 
        {
			0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            get { return Digests.Blake256; }
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
        public Blake256()
        {
            Initialize();
        }


        /// <summary>
        /// Initialize the class with a salt value
        /// </summary>
        /// 
        /// <param name="Salt">The optional salt value; must be 4 uint in length</param>
        public Blake256(int[] Salt)
        {
            if (Salt.Length != 4)
                throw new CryptoHashException("Blake256:Ctor", "The Salt array length must be 4!", new ArgumentOutOfRangeException());

            Array.Copy(Salt, _salt32, _salt32.Length);
            Initialize();
        }


        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Blake256()
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
                throw new CryptoHashException("Blake256:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            int offset = InOffset;
            int fill = 64 - _dataLen;

            // compress remaining data filled with new bits
            if ((_dataLen > 0) && (Length >= fill))
            {
                Array.Copy(Input, offset, _msgState, _dataLen, fill);
                _T += TN_512;
                Compress(_msgState, 0);
                offset += fill;
                Length -= fill;
                _dataLen = 0;
            }

            // compress data until enough for a block
            while (Length >= 64)
            {
                _T += TN_512;
                Compress(Input, offset);
                offset += 64;
                Length -= 64;
            }

            if (Length > 0)
            {
                Array.Copy(Input, offset, _msgState, _dataLen, Length);
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
                throw new CryptoHashException("Blake256:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            byte[] msgLen = new byte[8];
            ulong len = _T + ((ulong)_dataLen << 3);

            IntUtils.Be32ToBytes((uint)((len >> 32) & 0xFFFFFFFFU), msgLen, 0);
            IntUtils.Be32ToBytes((uint)(len & 0xFFFFFFFFU), msgLen, 4);

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

                    _T -= TN_440 - ((ulong)_dataLen << 3);
                    BlockUpdate(_Padding, 0, PAD_LENGTH - _dataLen);
                }
                else
                {
                    // not enough space, need 2 compressions
                    _T -= TN_512 - ((ulong)_dataLen << 3);
                    BlockUpdate(_Padding, 0, 64 - _dataLen);
                    _T -= TN_440;
                    BlockUpdate(_Padding, 1, PAD_LENGTH);
                    _isNullT = true;
                }

                BlockUpdate(new byte[1] { 0x01 }, 0, 1);
                _T -= 8;
            }

            _T -= 64;
            BlockUpdate(msgLen, 0, 8);
            byte[] digest = new byte[32];

            IntUtils.Be32ToBytes(_hashVal[0], digest, 0);
            IntUtils.Be32ToBytes(_hashVal[1], digest, 4);
            IntUtils.Be32ToBytes(_hashVal[2], digest, 8);
            IntUtils.Be32ToBytes(_hashVal[3], digest, 12);
            IntUtils.Be32ToBytes(_hashVal[4], digest, 16);
            IntUtils.Be32ToBytes(_hashVal[5], digest, 20);
            IntUtils.Be32ToBytes(_hashVal[6], digest, 24);
            IntUtils.Be32ToBytes(_hashVal[7], digest, 28);

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
            _M[0] = IntUtils.BytesToBe32(Block, Offset);
            _M[1] = IntUtils.BytesToBe32(Block, Offset + 4);
            _M[2] = IntUtils.BytesToBe32(Block, Offset + 8);
            _M[3] = IntUtils.BytesToBe32(Block, Offset + 12);
            _M[4] = IntUtils.BytesToBe32(Block, Offset + 16);
            _M[5] = IntUtils.BytesToBe32(Block, Offset + 20);
            _M[6] = IntUtils.BytesToBe32(Block, Offset + 24);
            _M[7] = IntUtils.BytesToBe32(Block, Offset + 28);
            _M[8] = IntUtils.BytesToBe32(Block, Offset + 32);
            _M[9] = IntUtils.BytesToBe32(Block, Offset + 36);
            _M[10] = IntUtils.BytesToBe32(Block, Offset + 40);
            _M[11] = IntUtils.BytesToBe32(Block, Offset + 44);
            _M[12] = IntUtils.BytesToBe32(Block, Offset + 48);
            _M[13] = IntUtils.BytesToBe32(Block, Offset + 52);
            _M[14] = IntUtils.BytesToBe32(Block, Offset + 56);
            _M[15] = IntUtils.BytesToBe32(Block, Offset + 60);

            _V[0] = _hashVal[0];
            _V[1] = _hashVal[1];
            _V[2] = _hashVal[2];
            _V[3] = _hashVal[3];
            _V[4] = _hashVal[4];
            _V[5] = _hashVal[5];
            _V[6] = _hashVal[6];
            _V[7] = _hashVal[7];
            _V[8] = _salt32[0] ^ 0x243F6A88U;
            _V[9] = _salt32[1] ^ 0x85A308D3U;
            _V[10] = _salt32[2] ^ 0x13198A2EU;
            _V[11] = _salt32[3] ^ 0x03707344U;
            _V[12] = 0xA4093822U;
            _V[13] = 0x299F31D0U;
            _V[14] = 0x082EFA98U;
            _V[15] = 0xEC4E6C89U;

            if (!_isNullT)
            {
                uint uLen = (uint)(_T & 0xFFFFFFFFU);
                _V[12] ^= uLen;
                _V[13] ^= uLen;
                uLen = (uint)((_T >> 32) & 0xFFFFFFFFU);
                _V[14] ^= uLen;
                _V[15] ^= uLen;
            }

            uint index = 0;
            do
            {
                MixBlock(index);
                index++;

            } while (index != ROUNDS);

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
            _hashVal[0] ^= _salt32[0];
            _hashVal[1] ^= _salt32[1];
            _hashVal[2] ^= _salt32[2];
            _hashVal[3] ^= _salt32[3];
            _hashVal[4] ^= _salt32[0];
            _hashVal[5] ^= _salt32[1];
            _hashVal[6] ^= _salt32[2];
            _hashVal[7] ^= _salt32[3];
        }

        private void Initialize()
        {
            _hashVal = new uint[8] 
            { 
                0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 
                0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U 
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
			    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8
		    };

            _T = 0;
            _dataLen = 0;
            _isNullT = false;
            Array.Clear(_salt32, 0, _salt32.Length);
            Array.Clear(_msgState, 0, _msgState.Length);
        }

        void Mix(uint A, uint B, uint C, uint D, uint R, uint I)
        {
            uint P = (R << 4) + I;
            uint P0 = _ftSigma[P];
            uint P1 = _ftSigma[P + 1];

            _V[A] += _V[B] + (_M[P0] ^ _C32[P1]);
            _V[D] = IntUtils.RotateRight(_V[D] ^ _V[A], 16);
            _V[C] += _V[D];
            _V[B] = IntUtils.RotateRight(_V[B] ^ _V[C], 12);
            _V[A] += _V[B] + (_M[P1] ^ _C32[P0]);
            _V[D] = IntUtils.RotateRight(_V[D] ^ _V[A], 8);
            _V[C] += _V[D];
            _V[B] = IntUtils.RotateRight(_V[B] ^ _V[C], 7);
        }

        private void MixBlock(uint Index)
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
                    if (_salt32 != null)
                    {
                        Array.Clear(_salt32, 0, _salt32.Length);
                        _salt32 = null;
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
