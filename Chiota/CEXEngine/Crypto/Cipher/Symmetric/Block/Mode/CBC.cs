#region Directives
using System;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// Implementation Details:
// An implementation of a Cipher Block Chaining mode (CBC).
// Written by John Underhill, September 24, 2014
// Updated October 8, 2016
// Contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// Implements the Cipher Block Chaining Mode (CBC)
    /// </summary> 
    /// 
    /// <example>
    /// <description>Encrypting a single block of bytes:</description>
    /// <code>
    /// using (ICipherMode cipher = new CBC(BlockCiphers.RHX))
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
    /// <para>The Cipher Block Chaining cipher mode wraps a symmetric block cipher, enabling the processing of multiple contiguous input blocks to produce a unique cipher-text output.<BR></BR>
    /// The mechanism used in CBC mode can be described as XOR chaining of message input blocks; the first block is XOR'd with the initialization vector, then encrypted with the underlying symmetric cipher.
    /// The second block is XOR'd with the first encrypted block, then encrypted, and all subsequent blocks follow this pattern.<BR></BR>
    /// The decryption function follows the reverse pattern; the block is decrypted with the symmetric cipher, and then XOR'd with the ciphertext from the previous block to produce the plain-text.</para>
    /// 
    /// <description><B>Description:</B></description>
    /// <para><EM>Legend:</EM><BR></BR> 
    /// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>E<SUP>-1</SUP></B>=decrypt, <B>^</B>=XOR<BR></BR><BR></BR>
    /// <EM>Encryption</EM><BR></BR>
    /// C0 ← IV. For 1 ≤ j ≤ t, Cj ← EK(Cj−1 ^ Pj).<BR></BR>
    /// <EM>Decryption</EM><BR></BR>
    /// C0 ← IV. For 1 ≤ j ≤ t, Pj ← Cj−1 ^ E<SUP>−1</SUP>K(Cj).</para>
    ///
    /// <description><B>Multi-Threading:</B></description>
    /// <para>The encryption function of the CBC mode is limited by its dependency chain; that is, each block relies on information from the previous block, and so can not be multi-threaded.
    /// The decryption function however, is not limited by this dependency chain and can be parallelized via the use of simultaneous processing by multiple processor cores.<BR></BR>
    /// This is acheived by storing the starting vector, (the encrypted bytes), from offsets within the ciphertext stream, and then processing multiple blocks of cipher-text independently across threads.</para>
    ///
    /// <description><B>Implementation Notes:</B></description>
    /// <list type="bullet">
    /// <item><description>A cipher mode constructor can either be initialized with a block cipher instance, or using the block ciphers enumeration name.</description></item>
    /// <item><description>A block cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
    /// <item><description>The Transform functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
    /// <item><description>The DecryptBlock and EncryptBlock functions can be accessed through the class instance.</description></item>
    /// <item><description>The transformation methods can not be called until the Initialize(bool, KeyParams) function has been called.</description></item>
    /// <item><description>In CBC mode, only the decryption function can be processed in parallel.</description></item>
    /// <item><description>The ParallelOptions.MaxDegreeOfParallelism property can be used to modify the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
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
    public sealed class CBC : ICipherMode
    {
        #region Constants
        private const string ALG_NAME = "CBC";
        private const int MAXALLOC_MB100 = 100000000;
        private const int PRL_BLOCKCACHE = 32000;
        #endregion

        #region Fields
        private IBlockCipher m_blockCipher;
        private int m_blockSize = 0;
        private byte[] m_cbcIv;
        private byte[] m_cbcNextIv;
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
        /// Get: Underlying Cipher instance
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
            get { return CipherModes.CBC; }
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
            get { return (byte[])m_cbcIv.Clone(); }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get/Set: Parallel block size; must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return m_parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoSymmetricException("CBC:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoSymmetricException("CBC:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

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
                        throw new CryptoSymmetricException("CBC:ParallelOption", "MaxDegreeOfParallelism can not be less than 1!", new ArgumentException());
                    else if (value.MaxDegreeOfParallelism == 1)
                        m_isParallel = false;
                    else if (value.MaxDegreeOfParallelism % 2 != 0)
                        throw new CryptoSymmetricException("CBC:ParallelOption", "MaxDegreeOfParallelism can not be an odd number; must be either 1, or a divisible of 2!", new ArgumentException());
                    
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
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid Cipher type is used</exception>
        public CBC(BlockCiphers CipherType)
        {
            if (CipherType == BlockCiphers.None)
                throw new CryptoSymmetricException("CBC:CTor", "The Cipher type can not be none!", new ArgumentNullException());

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
        public CBC(IBlockCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoSymmetricException("CBC:CTor", "The Cipher can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_blockCipher = Cipher;
            m_blockSize = m_blockCipher.BlockSize;
            Scope();
        }

        private CBC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CBC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para>Decrypts one block of bytes beginning at a zero index.
        /// Initialize(bool, KeyParams) must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of encrypted bytes</param>
        /// <param name="Output">The output array of decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            DecryptBlock(Input, 0, Output, 0);
        }

        /// <summary>
        /// Decrypt a block of bytes with offset parameters.
        /// <para>Decrypts one block of bytes at the designated offsets.
        /// Initialize(bool, KeyParams) must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of encrypted bytes</param>
        /// <param name="InOffset">Starting offset within the Input array</param>
        /// <param name="Output">The output array of decrypted bytes</param>
        /// <param name="OutOffset">Starting offset within the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // copy input to temp iv
            Buffer.BlockCopy(Input, InOffset, m_cbcNextIv, 0, m_blockSize);
            // decrypt input
            m_blockCipher.DecryptBlock(Input, InOffset, Output, OutOffset);
            // xor output and iv
            IntUtils.XORBLK(m_cbcIv, 0, Output, OutOffset, m_cbcIv.Length);
            // copy forward iv
            Buffer.BlockCopy(m_cbcNextIv, 0, m_cbcIv, 0, m_cbcIv.Length);
        }

        /// <summary>
        /// Encrypt a single block of bytes. 
        /// <para>Encrypts one block of bytes beginning at a zero index.
        /// Initialize(bool, KeyParams) must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of plain text bytes</param>
        /// <param name="Output">The output array of encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            EncryptBlock(Input, 0, Output, 0);
        }

        /// <summary>
        /// Encrypt a block of bytes using offset parameters. 
        /// <para>Encrypts one block of bytes at the designated offsets.
        /// Initialize(bool, KeyParams) must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">The input array of plain text bytes</param>
        /// <param name="InOffset">Starting offset within the input array</param>
        /// <param name="Output">The output array of encrypted bytes</param>
        /// <param name="OutOffset">Starting offset within the output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // xor iv and input
            IntUtils.XORBLK(Input, InOffset, m_cbcIv, 0, m_cbcIv.Length);
            // encrypt iv
            m_blockCipher.EncryptBlock(m_cbcIv, 0, Output, OutOffset);
            // copy output to iv
            Buffer.BlockCopy(Output, OutOffset, m_cbcIv, 0, m_blockSize);
        }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParam containing key and vector</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Key or IV is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            // recheck params
            Scope();

            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("CBC:Initialize", "Key can not be null!", new ArgumentNullException());
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("CBC:Initialize", "IV can not be null!", new ArgumentNullException());
            if (IsParallel && ParallelBlockSize < ParallelMinimumSize || ParallelBlockSize > ParallelMaximumSize)
                throw new CryptoSymmetricException("CBC:Initialize", "The parallel block size is out of bounds!");
            if (IsParallel && ParallelBlockSize % ParallelMinimumSize != 0)
                throw new CryptoSymmetricException("CBC:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

            m_blockCipher.Initialize(Encryption, KeyParam);
            m_cbcIv = KeyParam.IV;
            m_cbcNextIv = new byte[m_cbcIv.Length];
            m_isEncryption = Encryption;
            m_isInitialized = true;
        }

        /// <summary>
        /// Transform a block of bytes.
        /// <para>Transforms one block of bytes beginning at a zero index.
        /// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.
        /// Multi-threading capable function in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
        /// Initialize(bool, KeyParams) must be called before this function can be used.</para>
        /// </summary>
        ///
        /// <param name="Input">The input array to transform</param>
        /// <param name="Output">The output array of transformed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (m_isEncryption)
            {
                EncryptBlock(Input, Output);
            }
            else
            {
                if (m_isParallel)
                    ParallelDecrypt(Input, Output);
                else
                    DecryptBlock(Input, Output);
            }
        }

        /// <summary>
        /// Transform a block of bytes using offset parameters.
        /// <para>Transforms one block of bytes using the designated offsets.
        /// Multi-threading capable function in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
        /// Initialize(bool, KeyParams) must be called before this method can be used.</para>
        /// </summary>
        ///
        /// <param name="Input">The input array to transform</param>
        /// <param name="InOffset">Starting offset within the input array</param>
        /// <param name="Output">The output array of transformed bytes</param>
        /// <param name="OutOffset">Starting offset within the output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (m_isEncryption)
            {
                EncryptBlock(Input, InOffset, Output, OutOffset);
            }
            else
            {
                if (m_isParallel)
                    ParallelDecrypt(Input, InOffset, Output, OutOffset);
                else
                    DecryptBlock(Input, InOffset, Output, OutOffset);
            }
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
                throw new CryptoSymmetricException("CBC:LoadCipher", "The block cipher could not be instantiated!", ex);
            }
        }

        private void ParallelDecrypt(byte[] Input, byte[] Output)
        {
            if (Output.Length < ParallelBlockSize)
            {
                int blocks = Output.Length / m_blockSize;

                // output is input xor with random
                for (int i = 0; i < blocks; i++)
                    DecryptBlock(Input, i * m_blockSize, Output, i * m_blockSize);
            }
            else
            {
                // parallel CBC decryption
                int cnkSize = ParallelBlockSize / ProcessorCount;
                int blkCount = (cnkSize / m_blockSize);
                byte[][] vectors = new byte[ProcessorCount][];

                for (int i = 0; i < ProcessorCount; i++)
                {
                    vectors[i] = new byte[m_blockSize];

                    // get the first iv
                    if (i != 0)
                        Buffer.BlockCopy(Input, (i * cnkSize) - m_blockSize, vectors[i], 0, m_blockSize);
                    else
                        Buffer.BlockCopy(m_cbcIv, 0, vectors[i], 0, m_blockSize);
                }

                System.Threading.Tasks.Parallel.For(0, ProcessorCount, ParallelOption, i =>
                {
                    for (int j = 0; j < blkCount; j++)
                        ProcessDecrypt(Input, (i * cnkSize) + (j * m_blockSize), Output, (i * cnkSize) + (j * m_blockSize), vectors[i]);
                });

                // copy the last vector to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, m_cbcIv, 0, m_cbcIv.Length);
            }
        }

        private void ParallelDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if ((Output.Length - OutOffset) < ParallelBlockSize)
            {
                int blocks = (Output.Length - OutOffset) / m_blockSize;

                // output is input xor with random
                for (int i = 0; i < blocks; i++)
                    DecryptBlock(Input, (i * m_blockSize) + InOffset, Output, (i * m_blockSize) + OutOffset);
            }
            else
            {
                // parallel CBC decryption //
                int cnkSize = ParallelBlockSize / ProcessorCount;
                int blkCount = (cnkSize / m_blockSize);
                byte[][] vectors = new byte[ProcessorCount][];

                for (int i = 0; i < ProcessorCount; i++)
                {
                    vectors[i] = new byte[m_blockSize];
                    // get the first iv
                    if (i != 0)
                        Buffer.BlockCopy(Input, (InOffset + (i * cnkSize)) - m_blockSize, vectors[i], 0, m_blockSize);
                    else
                        Buffer.BlockCopy(m_cbcIv, 0, vectors[i], 0, m_blockSize);
                }

                System.Threading.Tasks.Parallel.For(0, ProcessorCount, ParallelOption, i =>
                {
                    for (int j = 0; j < blkCount; j++)
                        ProcessDecrypt(Input, InOffset + (i * cnkSize) + (j * m_blockSize), Output, OutOffset + (i * cnkSize) + (j * m_blockSize), vectors[i]);
                });

                // copy the last vector to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, m_cbcIv, 0, m_cbcIv.Length);
            }
        }

        private void ProcessDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset, byte[] Vector)
        {
            byte[] nextIv = new byte[Vector.Length];

            // copy input to temp iv
            Buffer.BlockCopy(Input, InOffset, nextIv, 0, m_blockSize);
            // decrypt input
            m_blockCipher.DecryptBlock(Input, InOffset, Output, OutOffset);
            // xor output and iv
            IntUtils.XORBLK(Vector, 0, Output, OutOffset, Vector.Length);
            // copy forward iv
            Buffer.BlockCopy(nextIv, 0, Vector, 0, m_blockSize);
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

                    if (m_cbcIv != null)
                    {
                        Array.Clear(m_cbcIv, 0, m_cbcIv.Length);
                        m_cbcIv = null;
                    }
                    if (m_cbcNextIv != null)
                    {
                        Array.Clear(m_cbcNextIv, 0, m_cbcNextIv.Length);
                        m_cbcNextIv = null;
                    }
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
