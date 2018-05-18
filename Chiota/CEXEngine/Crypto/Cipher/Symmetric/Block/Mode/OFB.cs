#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
// An implementation of a Output FeedBack Mode (OFB).
// Written by John Underhill, January 2, 2015
// Updated October 8, 2016
// Contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// Implements a Output FeedBack Mode (OFB)
    /// </summary>
    /// 
    /// <example>
    /// <description>Encrypting a single block of bytes:</description>
    /// <code>
    /// using (ICipherMode cipher = new OFB(BlockCiphers.RHX))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, 0, Output, 0);
    /// }
    /// </code>
    /// </example>
    ///
    /// <remarks>
    /// <description><B>Overview:</B></description>
    /// <para>Output Feedback Mode (OFB) is a similar construction to the CFB mode, and allows encryption of various block sizes.<BR></BR>
    /// It differs in that the output of the encryption block function, (rather than the ciphertext), serves as the feedback register.<BR></BR>
    /// The cipher is initialized by copying the initialization vector to an internal register, prepended by zeroes.<BR></BR>
    /// During a transformation, this register is encrypted by the underlying cipher into a buffer, the buffer is then XOR'd with the input message block to produce the ciphertext.<BR></BR>
    /// The vector block is then rotated so that the latter half of the vector is shifted to the start of the array, and the buffer is moved to the end of the array.</para>
    /// 
    /// <description><B>Description:</B></description>
    /// <para><EM>Legend:</EM><BR></BR> 
    /// C=ciphertext, P=plaintext, K=key, E=encrypt, ^=XOR<BR></BR><BR></BR>
    /// <EM>Encryption</EM><BR></BR>
    /// I1 ← IV. For 1 ≤ j ≤ u, given plaintext block Pj:<BR></BR>
    /// (a) Oj ← EK(Ij). -Compute the block cipher output.<BR></BR>
    /// (b) Tj ← the r leftmost bits of Oj. -Assume the leftmost is identified as bit 1.<BR></BR>
    /// (c) Cj ← Pj ^ Tj. -Transmit the r-bit ciphertext block Cj.<BR></BR>
    /// (d) Ij+1 ← 2r · Ij + Tj mod 2n. -Update the block cipher input for the next block.<BR></BR>
    /// <EM>Decryption</EM><BR></BR>
    /// I1 ← IV . For 1 ≤ j ≤ u, upon receiving Cj:<BR></BR>
    /// Pj ← Cj ^ Tj, where Tj, Oj, and Ij are computed as an encryption cycle; K(C).</para>
    ///
    /// <description><B>Implementation Notes:</B></description>
    /// <list type="bullet">
    /// <item><description></description></item>
    /// <item><description>A cipher mode constructor can either be initialized with a block cipher instance, or using the block ciphers enumeration name.</description></item>
    /// <item><description>A block cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
    /// <item><description>The Transform functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
    /// <item><description>The DecryptBlock and EncryptBlock functions can only be accessed through the class instance.</description></item>
    /// <item><description>The transformation methods can not be called until the Initialize(bool, KeyParams) function has been called.</description></item>
    /// <item><description>Due to block chain depenencies in OFB mode, neither the encryption or decryption functions can be processed in parallel.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
    /// <item><description>FIPS <a href="http://csrc.nist.gov/publications/fips/fips81/fips81.htm">PUB81</a>.</description></item>
    /// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class OFB : ICipherMode
    {
        #region Constants
        private const string ALG_NAME = "OFB";
        #endregion

        #region Fields
        private IBlockCipher m_blockCipher;
        private int m_blockSize = 0;
        private bool m_disposeEngine = false;
        private bool m_isDisposed = false;
        private bool m_isEncryption = false;
        private bool m_isInitialized = false;
        private byte[] m_ofbIv;
        private byte[] m_ofbBuffer;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher
        /// </summary>
        public int BlockSize
        {
            get { return m_blockSize; }
            private set { m_blockSize = value; }
        }

        /// <summary>
        /// Get: Underlying Cipher
        /// </summary>
        public IBlockCipher Engine
        {
            get { return m_blockCipher; }
            private set { m_blockCipher = value; }
        }

        /// <summary>
        /// Get: The cipher modes type name
        /// </summary>
        public CipherModes Enumeral
        {
            get { return CipherModes.OFB; }
        }

        /// <summary>
        /// Get: Initialized for encryption, false for decryption
        /// </summary>
        public bool IsEncryption
        {
            get { return m_isEncryption; }
            private set { m_isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
            private set { m_isInitialized = value; }
        }

        /// <summary>
        /// Get: The current state of the initialization Vector
        /// </summary>
        public byte[] IV
        {
            get { return (byte[])m_ofbIv.Clone(); }
        }

        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return false; }
            set
            {
                if (value == true)
                    throw new CryptoSymmetricException("OFB:IsParallel", "The OFB cipher mode can not be parallelized!");
            }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return 0; }
            set
            {
                if (value != 0)
                    throw new CryptoSymmetricException("OFB:ParallelBlockSize", "The OFB cipher mode can not be parallelized!");
            }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public int ParallelMaximumSize
        {
            get { return 0; }
        }

        /// <summary>
        /// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
        /// </summary>
        public int ParallelMinimumSize
        {
            get { return 0; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the cipher mode using a block cipher type name
        /// </summary>
        /// 
        /// <param name="CipherType">The formal enumeration name of a block cipher</param>
        /// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the Block Ciphers internal block size</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid Cipher type or register size is used</exception>
        public OFB(BlockCiphers CipherType, int RegisterSize = 16)
        {
            if (CipherType == BlockCiphers.None)
                throw new CryptoSymmetricException("OFB:CTor", "The Cipher type can not be none!", new ArgumentNullException());
            if (RegisterSize == 0)
                throw new CryptoSymmetricException("OFB:CTor", "The RegisterSize can not be zero!");

            m_blockCipher = LoadCipher(CipherType);

            if (RegisterSize > m_blockCipher.BlockSize)
                throw new CryptoSymmetricException("OFB:CTor", "The RegisterSize can not be more than the ciphers block size!");

            m_disposeEngine = true;
            m_blockSize = RegisterSize;
            m_ofbIv = new byte[m_blockCipher.BlockSize];
            m_ofbBuffer = new byte[m_blockCipher.BlockSize];
        }

        /// <summary>
        /// Initialize the cipher mode with a block cipher instance
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        /// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the Block Ciphers internal block size</param>
        /// <param name="DisposeEngine">Dispose of block cipher when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Cipher or invalid register size is used</exception>
        public OFB(IBlockCipher Cipher, int RegisterSize = 16, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoSymmetricException("OFB:CTor", "The Cipher can not be null!", new ArgumentNullException());
            if (RegisterSize == 0)
                throw new CryptoSymmetricException("OFB:CTor", "The RegisterSize can not be zero!");
            if (RegisterSize > Cipher.BlockSize)
                throw new CryptoSymmetricException("OFB:CTor", "The RegisterSize can not be more than the ciphers block size!");

            m_blockCipher = Cipher;
            m_disposeEngine = DisposeEngine;
            m_blockSize = RegisterSize;
            m_ofbIv = new byte[m_blockCipher.BlockSize];
            m_ofbBuffer = new byte[m_blockCipher.BlockSize];
        }

        private OFB()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~OFB()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Encrypt a single block of bytes. 
        /// <para>Initialize(bool, KeyParams) must be called before this method can be used.
        /// Encrypts one block of bytes beginning at a zero index.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of plain text bytes</param>
        /// <param name="Output">The output array of encrypted bytes</param>
        void EncryptBlock(byte[] Input, byte[] Output)
        {
            EncryptBlock(Input, 0, Output, 0);
        }

        /// <summary>
        /// Encrypt a block of bytes using offset parameters. 
        /// <para>Initialize(bool, KeyParams) must be called before this method can be used.
        /// Encrypts one block of bytes at the designated offsets.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of plain text bytes</param>
        /// <param name="InOffset">Starting offset within the input array</param>
        /// <param name="Output">The output array of encrypted bytes</param>
        /// <param name="OutOffset">Starting offset within the output array</param>
        void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            m_blockCipher.Transform(m_ofbIv, 0, m_ofbBuffer, 0);

            // xor the iv with the plaintext producing the cipher text and the next input block
            for (int i = 0; i < m_blockSize; i++)
                Output[OutOffset + i] = (byte)(m_ofbBuffer[i] ^ Input[InOffset + i]);

            // change over the Input block.
            Buffer.BlockCopy(m_ofbIv, m_blockSize, m_ofbIv, 0, m_ofbIv.Length - m_blockSize);
            Buffer.BlockCopy(m_ofbBuffer, 0, m_ofbIv, m_ofbIv.Length - m_blockSize, m_blockSize);
        }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">The KeyParams containing the key and vector</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Key or IV is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("OFB:Initialize", "Key can not be null!", new ArgumentNullException());
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("OFB:Initialize", "IV can not be null!", new ArgumentNullException());

            m_blockCipher.Initialize(true, KeyParam);

            byte[] iv = KeyParam.IV;

            if (iv.Length < m_ofbIv.Length)
            {
                // prepend the supplied IV with zeros per FIPS PUB 81
                Array.Copy(iv, 0, m_ofbIv, m_ofbIv.Length - iv.Length, iv.Length);

                for (int i = 0; i < m_ofbIv.Length - iv.Length; i++)
                    m_ofbIv[i] = 0;
            }
            else
            {
                Array.Copy(iv, 0, m_ofbIv, 0, m_ofbIv.Length);
            }

            m_isEncryption = Encryption;
            m_isInitialized = true;
        }

        /// <summary>
        /// Transform a block of bytes. 
        /// <para>Initialize(bool, KeyParams) must be called before this method can be used.
        /// Encrypts one block of bytes beginning at a zero index.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of bytes to transform</param>
        /// <param name="Output">The output array of transformed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            EncryptBlock(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes with offset parameters. 
        /// <para>Initialize(bool, KeyParams) must be called before this method can be used.
        /// Encrypts one block of bytes at the designated offsets.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of bytes to transform</param>
        /// <param name="InOffset">Starting offset within the input array</param>
        /// <param name="Output">The output array of transformed bytes</param>
        /// <param name="OutOffset">Starting offset within the output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            EncryptBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Private Methods
        IBlockCipher LoadCipher(BlockCiphers CipherType)
        {
            try
            {
                return Helper.BlockCipherFromName.GetInstance(CipherType);
            }
            catch (Exception ex)
	        {
		        throw new CryptoSymmetricException("OFB:LoadCipher", "The block cipher could not be instantiated!", ex);
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (m_blockCipher != null && m_disposeEngine)
                        m_blockCipher.Dispose();

                    if (m_ofbIv != null)
                    {
                        Array.Clear(m_ofbIv, 0, m_ofbIv.Length);
                        m_ofbIv = null;
                    }
                    if (m_ofbBuffer != null)
                    {
                        Array.Clear(m_ofbBuffer, 0, m_ofbBuffer.Length);
                        m_ofbBuffer = null;
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
