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
// An implementation of the Blake digest with a 256 bit digest size.
// Written by John Underhill, January 12, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// <h3>Blake256: An implementation of the Blake digest with a 256 bit return size.</h3>
    /// <para>SHA-3 finalist<cite>NIST IR7896</cite>: The Blake<cite>Blake</cite> digest</para>
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
    /// <item><description>Block size is 32 bytes, (256 bits).</description></item>
    /// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
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
    public sealed class Blake256 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "Blake256";
        private const int BLOCK_SIZE = 32;
        private const int DIGEST_SIZE = 32;
        private const int PAD_LENGTH = 55;
        private const int ROUNDS = 14;
        private const UInt64 TN_440 = 440;
        private const UInt64 TN_512 = 512;
        #endregion

        #region Fields
        private int _dataLen = 0;
        private UInt32[] _hashVal = new UInt32[8];
        private bool _isDisposed = false;
        private bool _isNullT;
        private UInt32[] _salt64 = new UInt32[4];
        private static int[] _ftSigma;
        private byte[] _digestState = new byte[64];
        private UInt32[] _M = new UInt32[16];
        private ulong _T;
        private UInt32[] _V = new UInt32[16];

        private static readonly UInt32[] _C32 = new UInt32[16] 
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
                Array.Copy(Input, offset, _digestState, _dataLen, fill);
                _T += TN_512;
                Compress32(_digestState, 0);
                offset += fill;
                Length -= fill;
                _dataLen = 0;
            }

            // compress data until enough for a block
            while (Length >= 64)
            {
                _T += TN_512;
                Compress32(Input, offset);
                offset += 64;
                Length -= 64;
            }

            if (Length > 0)
            {
                Array.Copy(Input, offset, _digestState, _dataLen, Length);
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

            UInt32ToBytes((UInt32)((len >> 32) & 0xFFFFFFFFU), msgLen, 0);
            UInt32ToBytes((UInt32)(len & 0xFFFFFFFFU), msgLen, 4);

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

                    _T -= TN_440 - ((UInt64)_dataLen << 3);
                    BlockUpdate(_Padding, 0, PAD_LENGTH - _dataLen);
                }
                else
                {
                    // not enough space, need 2 compressions
                    _T -= TN_512 - ((UInt64)_dataLen << 3);
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

            for (int i = 0; i < 8; ++i)
                UInt32ToBytes(_hashVal[i], digest, i << 2);

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
        private static UInt32 BytesToUInt32(byte[] Input, int InOffset)
        {
            return ((UInt32)Input[InOffset + 3] |
                ((UInt32)Input[InOffset + 2] << 8) |
                ((UInt32)Input[InOffset + 1] << 16) |
                ((UInt32)Input[InOffset] << 24));
        }

        private void G32(int A, int B, int C, int D, int R, int I)
        {
            int P = (R << 4) + I;
            int P0 = _ftSigma[P];
            int P1 = _ftSigma[P + 1];

            _V[A] += _V[B] + (_M[P0] ^ _C32[P1]);
            _V[D] = RotateRight(_V[D] ^ _V[A], 16);
            _V[C] += _V[D];
            _V[B] = RotateRight(_V[B] ^ _V[C], 12);
            _V[A] += _V[B] + (_M[P1] ^ _C32[P0]);
            _V[D] = RotateRight(_V[D] ^ _V[A], 8);
            _V[C] += _V[D];
            _V[B] = RotateRight(_V[B] ^ _V[C], 7);
        }

        private void Compress32(byte[] Block, int Offset)
        {
            for (int i = 0; i < 16; ++i)
                _M[i] = BytesToUInt32(Block, Offset + (i << 2));

            Array.Copy(_hashVal, _V, 8);

            _V[8] = _salt64[0] ^ 0x243F6A88U;
            _V[9] = _salt64[1] ^ 0x85A308D3U;
            _V[10] = _salt64[2] ^ 0x13198A2EU;
            _V[11] = _salt64[3] ^ 0x03707344U;
            _V[12] = 0xA4093822U;
            _V[13] = 0x299F31D0U;
            _V[14] = 0x082EFA98U;
            _V[15] = 0xEC4E6C89U;

            if (!_isNullT)
            {
                UInt32 uLen = (UInt32)(_T & 0xFFFFFFFFU);
                _V[12] ^= uLen;
                _V[13] ^= uLen;
                uLen = (UInt32)((_T >> 32) & 0xFFFFFFFFU);
                _V[14] ^= uLen;
                _V[15] ^= uLen;
            }

            for (int cnt = 0; cnt < ROUNDS; ++cnt)
            {
                G32(0, 4, 8, 12, cnt, 0);
                G32(1, 5, 9, 13, cnt, 2);
                G32(2, 6, 10, 14, cnt, 4);
                G32(3, 7, 11, 15, cnt, 6);
                G32(3, 4, 9, 14, cnt, 14);
                G32(2, 7, 8, 13, cnt, 12);
                G32(0, 5, 10, 15, cnt, 8);
                G32(1, 6, 11, 12, cnt, 10);
            }

            for (int i = 0; i < 8; ++i) 
                _hashVal[i] ^= _V[i];
            for (int i = 0; i < 8; ++i) 
                _hashVal[i] ^= _V[i + 8];
            for (int i = 0; i < 4; ++i) 
                _hashVal[i] ^= _salt64[i];
            for (int i = 0; i < 4; ++i) 
                _hashVal[i + 4] ^= _salt64[i];
        }

        private void Initialize()
        {
            _hashVal = new UInt32[8] 
            { 
                0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 
                0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U 
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
			    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8
		    };

            Array.Clear(_salt64, 0, _salt64.Length);

            _T = 0;
            _dataLen = 0;
            _isNullT = false;

            Array.Clear(_digestState, 0, _digestState.Length);
        }

        private static UInt32 RotateRight(UInt32 Input, int Bits)
        {
            return ((Input >> Bits) | (Input << (32 - Bits)));
        }

        private static void UInt32ToBytes(UInt32 Input, byte[] Output, int OutOffset)
        {
            for (int i = 3; i >= 0; --i)
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
