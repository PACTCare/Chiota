#region Directives
using System;
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
// The Skein Hash Function Family: <see href="https://www.schneier.com/skein1.3.pdf">Skein V1.1</see>.
// Implementation Details:
// An implementation of the Skein digest. 
// Written by John Underhill, January 13, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// <h3>Skein256: An implementation of the Skein digest with a 256 bit digest return size.</h3>
    /// <para>SHA-3 finalist<cite>NIST IR7896</cite>: The Skein<cite>Skein</cite> digest</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new Skein256())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Block size is 32 bytes, (256 bits).</description></item>
    /// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods, and resets the internal state.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method does NOT reset the internal state; call <see cref="Reset()"/> to reinitialize.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>The Skein Hash Function Family: <see href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</see>.</description></item>
    /// <item><description>Skein <see href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</see> Support for the Skein Hash Family.</description></item>
    /// <item><description>SHA3: <see href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent HashLib project implementation <see href="http://hashlib.codeplex.com/">Skein.cs</see> class.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Skein : IDigest, IDisposable // failing KATs.. tweaks?
    {
        #region Constants
        private const string ALG_NAME = "Skein256";
        private const int BLOCK_SIZE = 32;
        private const int DIGEST_SIZE = 32;
        private const int STATE_SIZE = 256;

        /*const int R_256_0_0 = 5;
        const int R_256_0_1 = 56;
        const int R_256_1_0 = 36;
        const int R_256_1_1 = 28;
        const int R_256_2_0 = 13;
        const int R_256_2_1 = 46;
        const int R_256_3_0 = 58;
        const int R_256_3_1 = 44;
        const int R_256_4_0 = 26;
        const int R_256_4_1 = 20;
        const int R_256_5_0 = 53;
        const int R_256_5_1 = 35;
        const int R_256_6_0 = 11;
        const int R_256_6_1 = 42;
        const int R_256_7_0 = 59;
        const int R_256_7_1 = 50;
        
        private const int R_256_0_0 = 14;
        private const int R_256_0_1 = 16;
        private const int R_256_1_0 = 52; 
        private const int R_256_1_1 = 57;
        private const int R_256_2_0 = 23; 
        private const int R_256_2_1 = 40;
        private const int R_256_3_0 = 5; 
        private const int R_256_3_1 = 37;
        private const int R_256_4_0 = 25; 
        private const int R_256_4_1 = 33;
        private const int R_256_5_0 = 46; 
        private const int R_256_5_1 = 12;
        private const int R_256_6_0 = 58; 
        private const int R_256_6_1 = 22;
        private const int R_256_7_0 = 32;
        private const int R_256_7_1 = 32;*/

        private static readonly ulong[] SKEIN_IV_224 =
        {
            0xB80929699AE0F431,
            0xD340DC14A06929DC,
            0xAE866594BDE4DC5A,
            0x339767C25A60EA1D
        };

        private static readonly ulong[] SKEIN_IV_256 =
        {
            0x388512680E660046,
            0x4B72D5DEC5A8FF01,
            0x281A9298CA5EB3A5,
            0x54CA5249F46070C4
        };
        #endregion
        
        #region Fields
        private int _blockSize = 0;
        private byte[] _buffer;
        private int _bufferIndex = 0;
        private int _digestSize = 0;
        private ulong _flags;
        private bool _isDisposed = false;
        private ulong[] _state = new ulong[4];
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _blockSize; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _digestSize; }
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
        /// 
        /// <param name="DigestSize">Digest return size in bits</param>
        public Skein(int DigestSize = 256)
        {
            // test for legal sizes; default at 256
            if (DigestSize == 224)
                _digestSize = 224 / 8;
            else
                _digestSize = 256 / 8;

            _blockSize = 32;

            Initialize();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Skein()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the SHA3 buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if (_bufferIndex != 0)
            {
                if (Length + _bufferIndex >= _blockSize)
                {
                    int chunkSize = _blockSize - _bufferIndex;
                    Buffer.BlockCopy(Input, InOffset, _buffer, _bufferIndex, chunkSize);
                    TransformBlock(_buffer, 0);
                    Length -= chunkSize;
                    InOffset += chunkSize;
                    _bufferIndex = 0;
                }
            }

            while (Length >= _buffer.Length)
            {
                TransformBlock(Input, InOffset);
                InOffset += _buffer.Length;
                Length -= _buffer.Length;
            }

            if (Length > 0)
            {
                Buffer.BlockCopy(Input, InOffset, _buffer, _bufferIndex, Length);
                _bufferIndex += Length;
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
        public int DoFinal(byte[] Output, int OutOffset)
        {
            _flags |= 0x8000000000000000;
            Array.Clear(_buffer, _bufferIndex, _buffer.Length - _bufferIndex); 
            TransformBlock(_buffer, 0);

            _flags = 0xff00000000000000;
            Array.Clear(_buffer, _bufferIndex, _buffer.Length - _bufferIndex); 
            _bufferIndex = 8;
            TransformBlock(_buffer, 0);

            Buffer.BlockCopy(ULongsToBytes(_state, 0, _state.Length), 0, Output, OutOffset, _digestSize);
            Initialize();

            return DigestSize;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            Initialize();
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            BlockUpdate(new byte[] { Input }, 0, 1);
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            _buffer = new byte[_blockSize];
            _flags = 0x7000000000000000;

            switch (_digestSize)
            {
                case 28: Array.Copy(SKEIN_IV_224, 0, _state, 0, SKEIN_IV_224.Length); 
                    break;
                case 32: Array.Copy(SKEIN_IV_256, 0, _state, 0, SKEIN_IV_256.Length); 
                    break;
            }
        }

        private void TransformBlock(byte[] Data, int Index)
        {
            ulong kw0, kw1, kw2, kw3, kw4, kw5, kw6, kw7;
            ulong X0, X1, X2, X3;
            const int R_256_0_0 = 5;
            const int R_256_0_1 = 56;
            const int R_256_1_0 = 36;
            const int R_256_1_1 = 28;
            const int R_256_2_0 = 13;
            const int R_256_2_1 = 46;
            const int R_256_3_0 = 58;
            const int R_256_3_1 = 44;
            const int R_256_4_0 = 26;
            const int R_256_4_1 = 20;
            const int R_256_5_0 = 53;
            const int R_256_5_1 = 35;
            const int R_256_6_0 = 11;
            const int R_256_6_1 = 42;
            const int R_256_7_0 = 59;
            const int R_256_7_1 = 50;

            kw0 = (ulong)_bufferIndex;
            kw1 = _flags;
            kw2 = kw0 ^ kw1;
            kw3 = _state[0];
            kw4 = _state[1];
            kw5 = _state[2];
            kw6 = _state[3];
            kw7 = kw3 ^ kw4 ^ kw5 ^ kw6 ^ 0x5555555555555555; //0x1BD11BDAA9FC1A22;

            ulong[] w = BytesToULongs(Data, Index, BlockSize);

            X0 = w[0] + kw3;
            X1 = w[1] + kw4 + kw0;
            X2 = w[2] + kw5 + kw1;
            X3 = w[3] + kw6;

            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw4;
            X1 += kw5 + kw1;
            X2 += kw6 + kw2;
            X3 += kw7 + 1;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw5;
            X1 += kw6 + kw2;
            X2 += kw7 + kw0;
            X3 += kw3 + 2;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw6;
            X1 += kw7 + kw0;
            X2 += kw3 + kw1;
            X3 += kw4 + 3;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw7;
            X1 += kw3 + kw1;
            X2 += kw4 + kw2;
            X3 += kw5 + 4;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw3;
            X1 += kw4 + kw2;
            X2 += kw5 + kw0;
            X3 += kw6 + 5;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw4;
            X1 += kw5 + kw0;
            X2 += kw6 + kw1;
            X3 += kw7 + 6;

            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw5;
            X1 += kw6 + kw1;
            X2 += kw7 + kw2;
            X3 += kw3 + 7;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw6;
            X1 += kw7 + kw2;
            X2 += kw3 + kw0;
            X3 += kw4 + 8;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw7;
            X1 += kw3 + kw0;
            X2 += kw4 + kw1;
            X3 += kw5 + 9;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw3;
            X1 += kw4 + kw1;
            X2 += kw5 + kw2;
            X3 += kw6 + 10;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw4;
            X1 += kw5 + kw2;
            X2 += kw6 + kw0;
            X3 += kw7 + 11;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw5;
            X1 += kw6 + kw0;
            X2 += kw7 + kw1;
            X3 += kw3 + 12;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw6;
            X1 += kw7 + kw1;
            X2 += kw3 + kw2;
            X3 += kw4 + 13;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw7;
            X1 += kw3 + kw2;
            X2 += kw4 + kw0;
            X3 += kw5 + 14;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw3;
            X1 += kw4 + kw0;
            X2 += kw5 + kw1;
            X3 += kw6 + 15;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw4;
            X1 += kw5 + kw1;
            X2 += kw6 + kw2;
            X3 += kw7 + 16;


            X0 += X1;
            X1 = (X1 << R_256_0_0) | (X1 >> (64 - R_256_0_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_0_1) | (X3 >> (64 - R_256_0_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_1_0) | (X3 >> (64 - R_256_1_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_1_1) | (X1 >> (64 - R_256_1_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_2_0) | (X1 >> (64 - R_256_2_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_2_1) | (X3 >> (64 - R_256_2_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_3_0) | (X3 >> (64 - R_256_3_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_3_1) | (X1 >> (64 - R_256_3_1));
            X1 ^= X2;
            X0 += kw5;
            X1 += kw6 + kw2;
            X2 += kw7 + kw0;
            X3 += kw3 + 17;
            X0 += X1;
            X1 = (X1 << R_256_4_0) | (X1 >> (64 - R_256_4_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_4_1) | (X3 >> (64 - R_256_4_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_5_0) | (X3 >> (64 - R_256_5_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_5_1) | (X1 >> (64 - R_256_5_1));
            X1 ^= X2;
            X0 += X1;
            X1 = (X1 << R_256_6_0) | (X1 >> (64 - R_256_6_0));
            X1 ^= X0;
            X2 += X3;
            X3 = (X3 << R_256_6_1) | (X3 >> (64 - R_256_6_1));
            X3 ^= X2;
            X0 += X3;
            X3 = (X3 << R_256_7_0) | (X3 >> (64 - R_256_7_0));
            X3 ^= X0;
            X2 += X1;
            X1 = (X1 << R_256_7_1) | (X1 >> (64 - R_256_7_1));
            X1 ^= X2;
            X0 += kw6;
            X1 += kw7 + kw0;
            X2 += kw3 + kw1;
            X3 += kw4 + 18;

            _state[0] = X0 ^ w[0];
            _state[1] = X1 ^ w[1];
            _state[2] = X2 ^ w[2];
            _state[3] = X3 ^ w[3];

            _flags = kw1 & ~(ulong)0x4000000000000000;
        }
        #endregion

        #region Helpers
        private static byte[] ULongsToBytes(ulong[] Input, int Index, int Length)
        {
            byte[] result = new byte[Length * 8];
            Buffer.BlockCopy(Input, Index, result, 0, result.Length);

            return result;
        }

        private static ulong[] BytesToULongs(byte[] Input, int Index, int Length)
        {
            ulong[] result = new ulong[Length / 8];
            Buffer.BlockCopy(Input, Index, result, 0, Length);

            return result;
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
                    if (_state != null)
                    {
                        Array.Clear(_state, 0, _state.Length);
                        _state = null;
                    }
                    if (_buffer != null)
                    {
                        Array.Clear(_buffer, 0, _buffer.Length);
                        _buffer = null;
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
