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
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 512 bit return size. 
// Refactoring, a couple of small optimizations, Dispose, and a ComputeHash method added.
// Many thanks to the authors of BouncyCastle for their great contributions.
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// <h3>SHA512: An implementation of the SHA-2 digest with a 512 bit digest return size.</h3>
    /// <para>The SHA-2<cite>Fips 180-4</cite> 512 digest</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new SHA512())
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
    /// <item><description>Block size is 128 bytes, (1024 bits).</description></item>
    /// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
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
    public sealed class SHA512 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "SHA512";
        private Int32 BLOCK_SIZE = 128;
        private Int32 DIGEST_SIZE = 64;
        #endregion

        #region Fields
        private long _btCounter1 = 0;
        private long _btCounter2 = 0;
        private int _bufferOffset = 0;
        private UInt64 _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7;
        private bool _isDisposed = false;
        private byte[] _prcBuffer = new byte[8];
        private UInt64[] _wordBuffer = new UInt64[80];
        private int _wordOffset = 0;
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
        public SHA512()
        {
			Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SHA512()
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
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoHashException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoHashException("SHA512:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            // fill the current word
            while ((_bufferOffset != 0) && (Length > 0))
            {
                Update(Input[InOffset]);

                InOffset++;
                Length--;
            }

            // process whole words.
            while (Length > _prcBuffer.Length)
            {
                ProcessWord(Input, InOffset);

                InOffset += _prcBuffer.Length;
                Length -= _prcBuffer.Length;
                _btCounter1 += _prcBuffer.Length;
            }

            // load in the remainder.
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
        /// <returns>Hash value [64 bytes]</returns>
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
        /// <returns>Size of Hash value, Always 64 bytes</returns>
        /// 
        /// <exception cref="CryptoHashException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < DigestSize)
                throw new CryptoHashException("SHA512:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            Finish();

            UInt64ToBE(_H0, Output, OutOffset);
            UInt64ToBE(_H1, Output, OutOffset + 8);
            UInt64ToBE(_H2, Output, OutOffset + 16);
            UInt64ToBE(_H3, Output, OutOffset + 24);
            UInt64ToBE(_H4, Output, OutOffset + 32);
            UInt64ToBE(_H5, Output, OutOffset + 40);
            UInt64ToBE(_H6, Output, OutOffset + 48);
            UInt64ToBE(_H7, Output, OutOffset + 56);

            Reset();

            return DIGEST_SIZE;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _btCounter1 = 0;
            _btCounter2 = 0;
            _bufferOffset = 0;

            for ( int i = 0; i < _prcBuffer.Length; i++ )
                _prcBuffer[i] = 0;

            _wordOffset = 0;
			Array.Clear(_wordBuffer, 0, _wordBuffer.Length);

            Initialize();
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _prcBuffer[_bufferOffset++] = Input;

            if (_bufferOffset == _prcBuffer.Length)
            {
                ProcessWord(_prcBuffer, 0);
                _bufferOffset = 0;
            }

            _btCounter1++;
        }
        #endregion

        #region Private Methods
        private void AdjustByteCounts()
        {
            if (_btCounter1 > 0x1fffffffffffffffL)
            {
                _btCounter2 += (Int64)((UInt64)_btCounter1 >> 61);
                _btCounter1 &= 0x1fffffffffffffffL;
            }
        }

        private void Finish()
        {
            AdjustByteCounts();

            long lowBitLen = _btCounter1 << 3;
            long hiBitLen = _btCounter2;

            // add the pad bytes.
            Update((byte)128);

            while (_bufferOffset != 0)
                Update((byte)0);

            ProcessLength(lowBitLen, hiBitLen);
            ProcessBlock();
        }

        private void Initialize()
        {
            _H0 = 0x6a09e667f3bcc908;
            _H1 = 0xbb67ae8584caa73b;
            _H2 = 0x3c6ef372fe94f82b;
            _H3 = 0xa54ff53a5f1d36f1;
            _H4 = 0x510e527fade682d1;
            _H5 = 0x9b05688c2b3e6c1f;
            _H6 = 0x1f83d9abfb41bd6b;
            _H7 = 0x5be0cd19137e2179;
        }

        private void ProcessBlock()
        {
            AdjustByteCounts();

            // expand 16 word block into 80 word blocks.
            for (int i = 16; i < 80; ++i)
                _wordBuffer[i] = Sigma1(_wordBuffer[i - 2]) + _wordBuffer[i - 7] + Sigma0(_wordBuffer[i - 15]) + _wordBuffer[i - 16];

            // set up working variables.
            UInt64 w0 = _H0;
            UInt64 w1 = _H1;
            UInt64 w2 = _H2;
            UInt64 w3 = _H3;
            UInt64 w4 = _H4;
            UInt64 w5 = _H5;
            UInt64 w6 = _H6;
            UInt64 w7 = _H7;
			int ctr = 0;

			for (int i = 0; i < 10; i ++)
			{
				// t = 8 * i
				w7 += Sum1(w4) + Ch(w4, w5, w6) + K[ctr] + _wordBuffer[ctr++];
				w3 += w7;
				w7 += Sum0(w0) + Maj(w0, w1, w2);
				// t = 8 * i + 1
				w6 += Sum1(w3) + Ch(w3, w4, w5) + K[ctr] + _wordBuffer[ctr++];
				w2 += w6;
				w6 += Sum0(w7) + Maj(w7, w0, w1);
				// t = 8 * i + 2
				w5 += Sum1(w2) + Ch(w2, w3, w4) + K[ctr] + _wordBuffer[ctr++];
				w1 += w5;
				w5 += Sum0(w6) + Maj(w6, w7, w0);
				// t = 8 * i + 3
				w4 += Sum1(w1) + Ch(w1, w2, w3) + K[ctr] + _wordBuffer[ctr++];
				w0 += w4;
				w4 += Sum0(w5) + Maj(w5, w6, w7);
				// t = 8 * i + 4
				w3 += Sum1(w0) + Ch(w0, w1, w2) + K[ctr] + _wordBuffer[ctr++];
				w7 += w3;
				w3 += Sum0(w4) + Maj(w4, w5, w6);
				// t = 8 * i + 5
				w2 += Sum1(w7) + Ch(w7, w0, w1) + K[ctr] + _wordBuffer[ctr++];
				w6 += w2;
				w2 += Sum0(w3) + Maj(w3, w4, w5);
				// t = 8 * i + 6
				w1 += Sum1(w6) + Ch(w6, w7, w0) + K[ctr] + _wordBuffer[ctr++];
				w5 += w1;
				w1 += Sum0(w2) + Maj(w2, w3, w4);
				// t = 8 * i + 7
				w0 += Sum1(w5) + Ch(w5, w6, w7) + K[ctr] + _wordBuffer[ctr++];
				w4 += w0;
				w0 += Sum0(w1) + Maj(w1, w2, w3);
			}

			_H0 += w0;
            _H1 += w1;
            _H2 += w2;
            _H3 += w3;
            _H4 += w4;
            _H5 += w5;
            _H6 += w6;
            _H7 += w7;

            // reset the offset and clean out the word buffer.
            _wordOffset = 0;
			Array.Clear(_wordBuffer, 0, 16);
		}

        private void ProcessLength(Int64 LowWord, Int64 HiWord)
        {
            if (_wordOffset > 14)
                ProcessBlock();

            _wordBuffer[14] = (UInt64)HiWord;
            _wordBuffer[15] = (UInt64)LowWord;
        }

        private void ProcessWord(byte[] Input, int InOffset)
        {
            _wordBuffer[_wordOffset] = BEToUInt64(Input, InOffset);

            if (++_wordOffset == 16)
                ProcessBlock();
        }
        #endregion

        #region Helpers
        private static UInt64 BEToUInt64(byte[] Input, int InOffset)
        {
            UInt32 hi = BEToUInt32(Input, InOffset);
            UInt32 lo = BEToUInt32(Input, InOffset + 4);

            return ((UInt64)hi << 32) | (UInt64)lo;
        }

        private static UInt32 BEToUInt32(byte[] Input, int InOffset)
        {
            UInt32 n = (UInt32)Input[InOffset] << 24;
            n |= (UInt32)Input[++InOffset] << 16;
            n |= (UInt32)Input[++InOffset] << 8;
            n |= (UInt32)Input[++InOffset];

            return n;
        }

        private static UInt64 Ch(UInt64 X, UInt64 Y, UInt64 Z)
        {
            return (X & Y) ^ (~X & Z);
        }

        private static UInt64 Maj(UInt64 X, UInt64 Y, UInt64 Z)
        {
            return (X & Y) ^ (X & Z) ^ (Y & Z);
        }

        private static UInt64 Sigma0(UInt64 X)
        {
            return ((X << 63) | (X >> 1)) ^ ((X << 56) | (X >> 8)) ^ (X >> 7);
        }

        private static UInt64 Sigma1(UInt64 X)
        {
            return ((X << 45) | (X >> 19)) ^ ((X << 3) | (X >> 61)) ^ (X >> 6);
        }

        private static UInt64 Sum0(UInt64 X)
        {
            return ((X << 36) | (X >> 28)) ^ ((X << 30) | (X >> 34)) ^ ((X << 25) | (X >> 39));
        }

        private static UInt64 Sum1(UInt64 X)
        {
            return ((X << 50) | (X >> 14)) ^ ((X << 46) | (X >> 18)) ^ ((X << 23) | (X >> 41));
        }

        private static void UInt64ToBE(UInt64 Input, byte[] Output, int OutOffset)
        {
            UInt32ToBE((UInt32)(Input >> 32), Output, OutOffset);
            UInt32ToBE((UInt32)(Input), Output, OutOffset + 4);
        }

        private static void UInt32ToBE(UInt32 Input, byte[] Output, int OutOffset)
        {
            Output[OutOffset] = (byte)(Input >> 24);
            Output[++OutOffset] = (byte)(Input >> 16);
            Output[++OutOffset] = (byte)(Input >> 8);
            Output[++OutOffset] = (byte)(Input);
        }
        #endregion

        #region Constant Tables
        internal static readonly UInt64[] K =
		{
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
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
                    if (_prcBuffer != null)
                    {
                        Array.Clear(_prcBuffer, 0, _prcBuffer.Length);
                        _prcBuffer = null;
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
