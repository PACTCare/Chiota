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
// An implementation of the SHA-2 digest with a 256 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
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
    /// SHA256: An implementation of the SHA-2 digest with a 256 bit digest return size
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
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Specification</a>.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SHA256 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "SHA256";
        private int BLOCK_SIZE = 64;
        private int DIGEST_SIZE = 32;
        #endregion

        #region Fields
        private int m_bufferOffset = 0;
        private long m_byteCount = 0;
        private byte[] m_processBuffer = new byte[4];
        private uint m_H0, m_H1, m_H2, m_H3, m_H4, m_H5, m_H6, m_H7;
        private bool m_isDisposed = false;
        private uint[] m_wordBuffer = new uint[64];
        private int m_wordOffset = 0;
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
            get { return Digests.SHA256; }
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
            while ((m_bufferOffset != 0) && (Length > 0))
            {
                Update(Input[InOffset]);
                InOffset++;
                Length--;
            }

            // process whole words
            while (Length > m_processBuffer.Length)
            {
                ProcessWord(Input, InOffset);

                InOffset += m_processBuffer.Length;
                Length -= m_processBuffer.Length;
                m_byteCount += m_processBuffer.Length;
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
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < DigestSize)
                throw new CryptoHashException("SHA256:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            Finish();

            IntUtils.Be32ToBytes(m_H0, Output, OutOffset);
            IntUtils.Be32ToBytes(m_H1, Output, OutOffset + 4);
            IntUtils.Be32ToBytes(m_H2, Output, OutOffset + 8);
            IntUtils.Be32ToBytes(m_H3, Output, OutOffset + 12);
            IntUtils.Be32ToBytes(m_H4, Output, OutOffset + 16);
            IntUtils.Be32ToBytes(m_H5, Output, OutOffset + 20);
            IntUtils.Be32ToBytes(m_H6, Output, OutOffset + 24);
            IntUtils.Be32ToBytes(m_H7, Output, OutOffset + 28);

            Reset();

            return DIGEST_SIZE;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            m_byteCount = 0;
            m_bufferOffset = 0;
            Array.Clear(m_processBuffer, 0, m_processBuffer.Length);

            Initialize();
        }

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            m_processBuffer[m_bufferOffset++] = Input;

            if (m_bufferOffset == m_processBuffer.Length)
            {
                ProcessWord(m_processBuffer, 0);
                m_bufferOffset = 0;
            }

            m_byteCount++;
        }
        #endregion

        #region Private Methods
        private void Finish()
        {
            long bitLength = (m_byteCount << 3);

            Update((byte)128);

            while (m_bufferOffset != 0)
                Update((byte)0);

            ProcessLength(bitLength);
            ProcessBlock();
        }

        private void Initialize()
        {
            // The first 32 bits of the fractional parts of the square roots of the first eight prime numbers
            m_H0 = 0x6a09e667;
            m_H1 = 0xbb67ae85;
            m_H2 = 0x3c6ef372;
            m_H3 = 0xa54ff53a;
            m_H4 = 0x510e527f;
            m_H5 = 0x9b05688c;
            m_H6 = 0x1f83d9ab;
            m_H7 = 0x5be0cd19;
        }

        private void ProcessBlock()
        {
            int ctr = 0;
            uint w0 = m_H0;
            uint w1 = m_H1;
            uint w2 = m_H2;
            uint w3 = m_H3;
            uint w4 = m_H4;
            uint w5 = m_H5;
            uint w6 = m_H6;
            uint w7 = m_H7;

            // expand 16 word block into 64 word blocks
            m_wordBuffer[16] = Theta1(m_wordBuffer[14]) + m_wordBuffer[9] + Theta0(m_wordBuffer[1]) + m_wordBuffer[0];
            m_wordBuffer[17] = Theta1(m_wordBuffer[15]) + m_wordBuffer[10] + Theta0(m_wordBuffer[2]) + m_wordBuffer[1];
            m_wordBuffer[18] = Theta1(m_wordBuffer[16]) + m_wordBuffer[11] + Theta0(m_wordBuffer[3]) + m_wordBuffer[2];
            m_wordBuffer[19] = Theta1(m_wordBuffer[17]) + m_wordBuffer[12] + Theta0(m_wordBuffer[4]) + m_wordBuffer[3];
            m_wordBuffer[20] = Theta1(m_wordBuffer[18]) + m_wordBuffer[13] + Theta0(m_wordBuffer[5]) + m_wordBuffer[4];
            m_wordBuffer[21] = Theta1(m_wordBuffer[19]) + m_wordBuffer[14] + Theta0(m_wordBuffer[6]) + m_wordBuffer[5];
            m_wordBuffer[22] = Theta1(m_wordBuffer[20]) + m_wordBuffer[15] + Theta0(m_wordBuffer[7]) + m_wordBuffer[6];
            m_wordBuffer[23] = Theta1(m_wordBuffer[21]) + m_wordBuffer[16] + Theta0(m_wordBuffer[8]) + m_wordBuffer[7];
            m_wordBuffer[24] = Theta1(m_wordBuffer[22]) + m_wordBuffer[17] + Theta0(m_wordBuffer[9]) + m_wordBuffer[8];
            m_wordBuffer[25] = Theta1(m_wordBuffer[23]) + m_wordBuffer[18] + Theta0(m_wordBuffer[10]) + m_wordBuffer[9];
            m_wordBuffer[26] = Theta1(m_wordBuffer[24]) + m_wordBuffer[19] + Theta0(m_wordBuffer[11]) + m_wordBuffer[10];
            m_wordBuffer[27] = Theta1(m_wordBuffer[25]) + m_wordBuffer[20] + Theta0(m_wordBuffer[12]) + m_wordBuffer[11];
            m_wordBuffer[28] = Theta1(m_wordBuffer[26]) + m_wordBuffer[21] + Theta0(m_wordBuffer[13]) + m_wordBuffer[12];
            m_wordBuffer[29] = Theta1(m_wordBuffer[27]) + m_wordBuffer[22] + Theta0(m_wordBuffer[14]) + m_wordBuffer[13];
            m_wordBuffer[30] = Theta1(m_wordBuffer[28]) + m_wordBuffer[23] + Theta0(m_wordBuffer[15]) + m_wordBuffer[14];
            m_wordBuffer[31] = Theta1(m_wordBuffer[29]) + m_wordBuffer[24] + Theta0(m_wordBuffer[16]) + m_wordBuffer[15];
            m_wordBuffer[32] = Theta1(m_wordBuffer[30]) + m_wordBuffer[25] + Theta0(m_wordBuffer[17]) + m_wordBuffer[16];
            m_wordBuffer[33] = Theta1(m_wordBuffer[31]) + m_wordBuffer[26] + Theta0(m_wordBuffer[18]) + m_wordBuffer[17];
            m_wordBuffer[34] = Theta1(m_wordBuffer[32]) + m_wordBuffer[27] + Theta0(m_wordBuffer[19]) + m_wordBuffer[18];
            m_wordBuffer[35] = Theta1(m_wordBuffer[33]) + m_wordBuffer[28] + Theta0(m_wordBuffer[20]) + m_wordBuffer[19];
            m_wordBuffer[36] = Theta1(m_wordBuffer[34]) + m_wordBuffer[29] + Theta0(m_wordBuffer[21]) + m_wordBuffer[20];
            m_wordBuffer[37] = Theta1(m_wordBuffer[35]) + m_wordBuffer[30] + Theta0(m_wordBuffer[22]) + m_wordBuffer[21];
            m_wordBuffer[38] = Theta1(m_wordBuffer[36]) + m_wordBuffer[31] + Theta0(m_wordBuffer[23]) + m_wordBuffer[22];
            m_wordBuffer[39] = Theta1(m_wordBuffer[37]) + m_wordBuffer[32] + Theta0(m_wordBuffer[24]) + m_wordBuffer[23];
            m_wordBuffer[40] = Theta1(m_wordBuffer[38]) + m_wordBuffer[33] + Theta0(m_wordBuffer[25]) + m_wordBuffer[24];
            m_wordBuffer[41] = Theta1(m_wordBuffer[39]) + m_wordBuffer[34] + Theta0(m_wordBuffer[26]) + m_wordBuffer[25];
            m_wordBuffer[42] = Theta1(m_wordBuffer[40]) + m_wordBuffer[35] + Theta0(m_wordBuffer[27]) + m_wordBuffer[26];
            m_wordBuffer[43] = Theta1(m_wordBuffer[41]) + m_wordBuffer[36] + Theta0(m_wordBuffer[28]) + m_wordBuffer[27];
            m_wordBuffer[44] = Theta1(m_wordBuffer[42]) + m_wordBuffer[37] + Theta0(m_wordBuffer[29]) + m_wordBuffer[28];
            m_wordBuffer[45] = Theta1(m_wordBuffer[43]) + m_wordBuffer[38] + Theta0(m_wordBuffer[30]) + m_wordBuffer[29];
            m_wordBuffer[46] = Theta1(m_wordBuffer[44]) + m_wordBuffer[39] + Theta0(m_wordBuffer[31]) + m_wordBuffer[30];
            m_wordBuffer[47] = Theta1(m_wordBuffer[45]) + m_wordBuffer[40] + Theta0(m_wordBuffer[32]) + m_wordBuffer[31];
            m_wordBuffer[48] = Theta1(m_wordBuffer[46]) + m_wordBuffer[41] + Theta0(m_wordBuffer[33]) + m_wordBuffer[32];
            m_wordBuffer[49] = Theta1(m_wordBuffer[47]) + m_wordBuffer[42] + Theta0(m_wordBuffer[34]) + m_wordBuffer[33];
            m_wordBuffer[50] = Theta1(m_wordBuffer[48]) + m_wordBuffer[43] + Theta0(m_wordBuffer[35]) + m_wordBuffer[34];
            m_wordBuffer[51] = Theta1(m_wordBuffer[49]) + m_wordBuffer[44] + Theta0(m_wordBuffer[36]) + m_wordBuffer[35];
            m_wordBuffer[52] = Theta1(m_wordBuffer[50]) + m_wordBuffer[45] + Theta0(m_wordBuffer[37]) + m_wordBuffer[36];
            m_wordBuffer[53] = Theta1(m_wordBuffer[51]) + m_wordBuffer[46] + Theta0(m_wordBuffer[38]) + m_wordBuffer[37];
            m_wordBuffer[54] = Theta1(m_wordBuffer[52]) + m_wordBuffer[47] + Theta0(m_wordBuffer[39]) + m_wordBuffer[38];
            m_wordBuffer[55] = Theta1(m_wordBuffer[53]) + m_wordBuffer[48] + Theta0(m_wordBuffer[40]) + m_wordBuffer[39];
            m_wordBuffer[56] = Theta1(m_wordBuffer[54]) + m_wordBuffer[49] + Theta0(m_wordBuffer[41]) + m_wordBuffer[40];
            m_wordBuffer[57] = Theta1(m_wordBuffer[55]) + m_wordBuffer[50] + Theta0(m_wordBuffer[42]) + m_wordBuffer[41];
            m_wordBuffer[58] = Theta1(m_wordBuffer[56]) + m_wordBuffer[51] + Theta0(m_wordBuffer[43]) + m_wordBuffer[42];
            m_wordBuffer[59] = Theta1(m_wordBuffer[57]) + m_wordBuffer[52] + Theta0(m_wordBuffer[44]) + m_wordBuffer[43];
            m_wordBuffer[60] = Theta1(m_wordBuffer[58]) + m_wordBuffer[53] + Theta0(m_wordBuffer[45]) + m_wordBuffer[44];
            m_wordBuffer[61] = Theta1(m_wordBuffer[59]) + m_wordBuffer[54] + Theta0(m_wordBuffer[46]) + m_wordBuffer[45];
            m_wordBuffer[62] = Theta1(m_wordBuffer[60]) + m_wordBuffer[55] + Theta0(m_wordBuffer[47]) + m_wordBuffer[46];
            m_wordBuffer[63] = Theta1(m_wordBuffer[61]) + m_wordBuffer[56] + Theta0(m_wordBuffer[48]) + m_wordBuffer[47];

            // t = 8 * i
            w7 += Sum1Ch(w4, w5, w6) + K32[ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            // t = 8 * i + 1
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            // t = 8 * i + 2
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            // t = 8 * i + 3
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            // t = 8 * i + 4
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            // t = 8 * i + 5
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            // t = 8 * i + 6
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            // t = 8 * i + 7
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            w7 += Sum1Ch(w4, w5, w6) + K32[++ctr] + m_wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0Maj(w0, w1, w2);
            w6 += Sum1Ch(w3, w4, w5) + K32[++ctr] + m_wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0Maj(w7, w0, w1);
            w5 += Sum1Ch(w2, w3, w4) + K32[++ctr] + m_wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0Maj(w6, w7, w0);
            w4 += Sum1Ch(w1, w2, w3) + K32[++ctr] + m_wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0Maj(w5, w6, w7);
            w3 += Sum1Ch(w0, w1, w2) + K32[++ctr] + m_wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0Maj(w4, w5, w6);
            w2 += Sum1Ch(w7, w0, w1) + K32[++ctr] + m_wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0Maj(w3, w4, w5);
            w1 += Sum1Ch(w6, w7, w0) + K32[++ctr] + m_wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0Maj(w2, w3, w4);
            w0 += Sum1Ch(w5, w6, w7) + K32[++ctr] + m_wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0Maj(w1, w2, w3);

            m_H0 += w0;
            m_H1 += w1;
            m_H2 += w2;
            m_H3 += w3;
            m_H4 += w4;
            m_H5 += w5;
            m_H6 += w6;
            m_H7 += w7;

            // reset the offset and clear the word buffer
            m_wordOffset = 0;
            Array.Clear(m_wordBuffer, 0, 16);
        }

        private void ProcessLength(long BitLength)
        {
            if (m_wordOffset > 14)
                ProcessBlock();

            m_wordBuffer[14] = (uint)((ulong)BitLength >> 32);
            m_wordBuffer[15] = (uint)((ulong)BitLength);
        }

        private void ProcessWord(byte[] Input, int Offset)
        {
            m_wordBuffer[m_wordOffset] = IntUtils.BytesToBe32(Input, Offset);

            if (++m_wordOffset == 16)
                ProcessBlock();
        }
        #endregion

        #region Helpers
        private static uint Sum1Ch(uint X, uint Y, uint Z)
        {
            return (((X >> 6) | (X << 26)) ^ ((X >> 11) | (X << 21)) ^ ((X >> 25) | (X << 7))) + ((X & Y) ^ ((~X) & Z));
        }

        private static uint Sum0Maj(uint X, uint Y, uint Z)
        {
            return (((X >> 2) | (X << 30)) ^ ((X >> 13) | (X << 19)) ^ ((X >> 22) | (X << 10))) + ((X & Y) ^ (X & Z) ^ (Y & Z));
        }

        private static uint Theta0(uint X)
        {
            return ((X >> 7) | (X << 25)) ^ ((X >> 18) | (X << 14)) ^ (X >> 3);
        }

        private static uint Theta1(uint X)
        {
            return ((X >> 17) | (X << 15)) ^ ((X >> 19) | (X << 13)) ^ (X >> 10);
        }
        #endregion

        #region Constant Tables
        /// <remarks>
        /// the first 32 bits of the fractional parts of the cube roots of the first sixty-four prime numbers)
        /// </remarks>
        private static readonly uint[] K32 = { 
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
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (m_processBuffer != null)
                    {
                        Array.Clear(m_processBuffer, 0, m_processBuffer.Length);
                        m_processBuffer = null;
                    }
                    if (m_wordBuffer != null)
                    {
                        Array.Clear(m_wordBuffer, 0, m_wordBuffer.Length);
                        m_wordBuffer = null;
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
