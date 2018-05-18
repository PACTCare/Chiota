#region Directives
using System;
using System.Threading.Tasks;
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
// An implementation of an Electronic CodeBook Mode (ECB).
// Written by John Underhill, September 24, 2014
// Updated October 8, 2016
// Contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// Implements an Electronic CodeBook Mode (ECB) 
    /// <para>ECB is an Insecure Mode; used only for testing purposes.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Encrypting a single block of bytes:</description>
    /// <code>
    /// using (ICipherMode cipher = new ECB(BlockCiphers.RHX))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key));
    ///     // encrypt a block
    ///     cipher.Transform(Input, 0, Output, 0);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description><B>Overview:</B></description>
    /// <para>The Electronic Code Book cipher processes message input directly through the underlying block cipher. 
    /// No Initialization Vector is used, and the output from each block does not effect the output of any other block.<BR></BR>
    /// For this reason, ECB is not considered a secure cipher mode, and should never be used in the transformation of real data, but only for debugging and performance testing.</para>
    /// 
    /// <description><B>Description:</B></description>
    /// <para><EM>Legend:</EM><BR></BR> 
    /// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>E<SUP>-1</SUP></B>=decrypt<BR></BR><BR></BR>
    /// <EM>Encryption</EM><BR></BR>
    /// For 1 ≤ j ≤ t, Cj ← EK(Pj).<BR></BR>
    /// <EM>Decryption</EM><BR></BR>
    /// For 1 ≤ j ≤ t, Pj ← E<SUP>−1</SUP>K(Cj).</para>
    ///
    /// <description><B>Multi-Threading:</B></description>
    /// <para>The encryption and decryption functions of the ECB mode be multi-threaded.<BR></BR> 
    /// This is acheived by processing multiple blocks of cipher-text independently across threads.</para>
    ///
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>ECB is not a secure mode, and should only be used for testing, timing, or as a base class; i.e. when constructing an authenticated mode.</description></item>
    /// <item><description>Encryption and decryption can both be multi-threaded.</description></item>
    /// <item><description>The IsParallel property is enabled automatically if the system has more than one processor core.</description></item>
    /// <item><description>Parallel processing is enabled when the IsParallel property is set to true, and an input block of ParallelBlockSize is passed to the transform.</description></item>
    /// <item><description>ParallelBlockSize is calculated automatically but can be user defined, but must be evenly divisible by ParallelMinimumSize.</description></item>
    /// <item><description>Parallel block calculation ex. <c>ParallelBlockSize = (data.Length / cipher.ParallelMinimumSize) * 40</c></description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
    /// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class ECB : ICipherMode
    {
        #region Constants
        private const string ALG_NAME = "ECB";
        private const int BLOCK_SIZE = 1024;
        private const int MAXALLOC_MB100 = 100000000;
        private const int PRL_BLOCKCACHE = 32000;
        #endregion

        #region Fields
        private IBlockCipher m_blockCipher;
        private int m_blockSize = 0;
        private bool m_disposeEngine = false;
        private bool m_isDisposed = false;
        private bool m_isEncryption = false;
        private bool m_isInitialized = false;
        private bool m_isLoaded = false;
        private bool m_isParallel = false;
        private int m_parallelBlockSize = 0;
        private int m_parallelMinimumSize = 0;
        private ParallelOptions m_parallelOption = null;
        private int m_processorCount = 1;
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
            get { return CipherModes.ECB; }
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
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return m_isParallel; }
            set { m_isParallel = value; }
        }

        /// <summary>
        /// Get: The current state of the initialization Vector
        /// </summary>
        public byte[] IV
        {
            get { throw new NotImplementedException(); }
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
            get { return m_parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoSymmetricException("ECB:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoSymmetricException("ECB:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

                m_parallelBlockSize = value;
            }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public int ParallelMaximumSize
        {
            get { return MAXALLOC_MB100; }
        }

        /// <summary>
        /// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
        /// </summary>
        public int ParallelMinimumSize
        {
            get { return m_parallelMinimumSize; }
        }

        /// <summary>
        /// Get/Set: The parallel loops ParallelOptions
        /// <para>The MaxDegreeOfParallelism of the parallel loop is equal to the Environment.ProcessorCount by default</para>
        /// </summary>
        public ParallelOptions ParallelOption
        {
            get
            {
                if (m_parallelOption == null)
                    m_parallelOption = new ParallelOptions() { MaxDegreeOfParallelism = Environment.ProcessorCount };

                return m_parallelOption;
            }
            set
            {
                if (value != null)
                {
                    if (value.MaxDegreeOfParallelism < 1)
                        throw new CryptoSymmetricException("ECB:ParallelOption", "MaxDegreeOfParallelism can not be less than 1!", new ArgumentException());
                    else if (value.MaxDegreeOfParallelism == 1)
                        m_isParallel = false;
                    else if (value.MaxDegreeOfParallelism % 2 != 0)
                        throw new CryptoSymmetricException("ECB:ParallelOption", "MaxDegreeOfParallelism can not be an odd number; must be either 1, or a divisible of 2!", new ArgumentException());

                    m_parallelOption = value;
                }
            }
        }

        /// <remarks>
        /// Get: Processor count
        /// </remarks>
        private int ProcessorCount
        {
            get { return m_processorCount; }
            set { m_processorCount = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the cipher mode using a block cipher type name
        /// </summary>
        /// 
        /// <param name="CipherType">The formal enumeration name of a block cipher</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if an invalid Cipher type is used</exception>
        public ECB(BlockCiphers CipherType)
        {
            if (CipherType == BlockCiphers.None)
                throw new CryptoSymmetricException("ECB:CTor", "The Cipher type can not be none!", new ArgumentNullException());

            m_disposeEngine = true;
            m_blockCipher = LoadCipher(CipherType);
            m_blockSize = m_blockCipher.BlockSize;
            Scope();
        }

        /// <summary>
        /// Initialize the cipher mode with a block cipher instance
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        /// <param name="DisposeEngine">Dispose of block cipher when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Cipher is used</exception>
        public ECB(IBlockCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoSymmetricException("ECB:CTor", "The Cipher can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_blockCipher = Cipher;
            m_blockSize = m_blockCipher.BlockSize;
            Scope();
        }

        private ECB()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~ECB()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            m_blockCipher.DecryptBlock(Input, Output);
        }

        /// <summary>
        /// Decrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            m_blockCipher.DecryptBlock(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Encrypt a block of bytes. 
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            m_blockCipher.EncryptBlock(Input, Output);
        }

        /// <summary>
        /// Encrypt a block of bytes with offset parameters. 
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            m_blockCipher.EncryptBlock(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParam containing key and vector</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Key is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            // recheck params
            Scope();

            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("ECB:Initialize", "Key can not be null!", new ArgumentNullException());
            if (IsParallel && ParallelBlockSize < ParallelMinimumSize || ParallelBlockSize > ParallelMaximumSize)
                throw new CryptoSymmetricException("ECB:Initialize", "The parallel block size is out of bounds!");
            if (IsParallel && ParallelBlockSize % ParallelMinimumSize != 0)
                throw new CryptoSymmetricException("ECB:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

            m_blockCipher.Initialize(Encryption, KeyParam);
            m_isEncryption = Encryption;
            m_isInitialized = true;
        }

        /// <summary>
        /// Transform a block of bytes. 
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Bytes to Transform</param>
        /// <param name="Output">Transformed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            Transform(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes with offset parameters. 
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Transform</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Transformed bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (m_isParallel)
            {
                if ((Output.Length - OutOffset) < m_parallelBlockSize)
                {
                    int blocks = (Output.Length - OutOffset) / m_blockSize;

                    for (int i = 0; i < blocks; i++)
                        m_blockCipher.Transform(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
                }
                else
                {
                    TransformParallel(Input, InOffset, Output, OutOffset);
                }
            }
            else
            {
                m_blockCipher.Transform(Input, InOffset, Output, OutOffset);
            }
        }
        #endregion

        #region Private Methods
        void Generate(byte[] Input, int InOffset, byte[] Output, int OutOffset, int BlockCount)
        {
            int blkCnt = BlockCount;

            while (blkCnt != 0)
            {
                m_blockCipher.Transform(Input, InOffset, Output, OutOffset);
                InOffset += m_blockSize;
                OutOffset += m_blockSize;
                --blkCnt;
            }
        }

        IBlockCipher LoadCipher(BlockCiphers CipherType)
        {
            try
            {
                return Helper.BlockCipherFromName.GetInstance(CipherType);
            }
            catch (Exception ex)
            {
                throw new CryptoSymmetricException("ECB:LoadCipher", "The block cipher could not be instantiated!", ex);
            }
        }

        void Scope()
        {
            m_processorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            if (m_processorCount > 1)
            {
                if (m_parallelOption != null && m_parallelOption.MaxDegreeOfParallelism > 0 && (m_parallelOption.MaxDegreeOfParallelism % 2 == 0))
                    m_processorCount = m_parallelOption.MaxDegreeOfParallelism;
                else
                    m_parallelOption = new ParallelOptions() { MaxDegreeOfParallelism = m_processorCount };
            }

            m_parallelMinimumSize = m_processorCount * m_blockCipher.BlockSize;
            m_parallelBlockSize = m_processorCount * PRL_BLOCKCACHE;

            if (!m_isLoaded)
            {
                m_isParallel = (m_processorCount > 1);
                m_isLoaded = true;
            }
        }

        void TransformParallel(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int segSze = m_parallelBlockSize / ProcessorCount;
            int blkCnt = (segSze / m_blockSize);

            System.Threading.Tasks.Parallel.For(0, ProcessorCount, ParallelOption, i =>
            {
		        Generate(Input, InOffset + i * segSze, Output, OutOffset + i * segSze, blkCnt);
            });
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
                }
                finally
                {
                    m_isLoaded = false;
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
