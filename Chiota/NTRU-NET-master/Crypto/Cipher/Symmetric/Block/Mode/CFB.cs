#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
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
// Implementation Details:
// An implementation of a Cipher FeedBack Mode (CFB).
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// <h3>Implements a Cipher FeedBack Mode: CFB.</h3>
    /// <para>CFB as outlined in the NIST document: SP800-38A<cite>SP800-38A</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CFB(new RDX(), [BlockSizeBits], [DisposeEngine]))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">VTDev.Libraries.CEXEngine.Crypto.Engines Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Parallel processing is enabled on decryption by passing a block size of <see cref="ParallelBlockSize"/> to the transform.</description></item>
    /// <item><description><see cref="ParallelBlockSize"/> must be divisible by <see cref="ParallelMinimumSize"/>.</description></item>
    /// <item><description>Parallel block calculation ex. <c>int blocklen = (data.Length / cipher.ParallelMinimumSize) * 10</c></description></item>
    /// <item><description>Cipher Engine is automatically disposed of unless DisposeEngine is set to <c>false</c> in the class constructor <see cref="CBC(IBlockCipher, bool)"/></description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST: <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CFB : ICipherMode
    {
        #region Constants
        private const string ALG_NAME = "CFB";
        private const int MAXALLOC_MB100 = 100000000;
        private const Int32 PARALLEL_DEFBLOCK = 64000;
        #endregion

        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private byte[] _cfbIv;
        private byte[] _cfbBuffer;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _parallelBlockSize = PARALLEL_DEFBLOCK;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher
        /// </summary>
        public int BlockSize
        {
            get { return _blockSize; }
            private set { _blockSize = value; }
        }

        /// <summary>
        /// Get: Underlying Cipher
        /// </summary>
        public IBlockCipher Engine
        {
            get { return _blockCipher; }
            private set { _blockCipher = value; }
        }

        /// <summary>
        /// Get: Initialized for encryption, false for decryption
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: The current state of the initialization Vector
        /// </summary>
        public byte[] IV
        {
            get { return (byte[])_cfbIv.Clone(); }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _isParallel; }
            set
            {
                if (ProcessorCount < 2)
                    _isParallel = false;
                else
                    _isParallel = value;
            }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoSymmetricException("CFB:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoSymmetricException("CFB:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

                _parallelBlockSize = value;
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
            get { return ProcessorCount * BlockSize; }
        }

        /// <remarks>
        /// Processor count
        /// </remarks>
        private int ProcessorCount { get; set; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        /// <param name="BlockSizeBits">Block size in bits; minimum is 8, or 1 byte. Maximum is Cipher block size in bits</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Cipher or valid block size is used</exception>
        public CFB(IBlockCipher Cipher, int BlockSizeBits = 128, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoSymmetricException("CFB:CTor", "The Cipher can not be null!", new ArgumentNullException());
            if (BlockSizeBits % 8 != 0)
                throw new CryptoSymmetricException("CFB:CTor", "Invalid block size! Block must be in bits and a multiple of 8.", new ArgumentException());
            if (BlockSizeBits / 8 > Cipher.BlockSize)
                throw new CryptoSymmetricException("CFB:CTor", "Invalid block size! Block size can not be larger than Cipher block size.", new ArgumentException());

            _disposeEngine = DisposeEngine;
            _blockCipher = Cipher;
            _blockSize = BlockSizeBits / 8;

            _cfbIv = new byte[Cipher.BlockSize];
            _cfbBuffer = new byte[Cipher.BlockSize];

            // one of those.. what if? things
            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        private CFB()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CFB()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is used. for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParams containing key and vector</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Key or IV is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("CFB:Initialize", "Key can not be null!", new ArgumentNullException());
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("CFB:Initialize", "IV can not be null!", new ArgumentNullException());

            byte[] iv = KeyParam.IV;
            int diff = _cfbIv.Length - iv.Length;

            Buffer.BlockCopy(iv, 0, _cfbIv, diff, iv.Length);
            Array.Clear(_cfbIv, 0, diff);

            _blockCipher.Initialize(true, KeyParam);
            _isEncryption = Encryption;
            _isInitialized = true;
        }

        /// <summary>
        /// <para>Decrypt a single block of bytes. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            _blockCipher.Transform(_cfbIv, 0, _cfbBuffer, 0);

            // change over the input block.
            Buffer.BlockCopy(_cfbIv, _blockSize, _cfbIv, 0, _cfbIv.Length - _blockSize);
            Buffer.BlockCopy(Input, 0, _cfbIv, _cfbIv.Length - _blockSize, _blockSize);

            // XOR the IV with the ciphertext producing the plaintext
            for (int i = 0; i < _blockSize; i++)
                Output[i] = (byte)(_cfbBuffer[i] ^ Input[i]);
        }

        /// <summary>
        /// <para>Decrypt a block of bytes with offset parameters. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            _blockCipher.Transform(_cfbIv, 0, _cfbBuffer, 0);

            // change over the input block.
            Buffer.BlockCopy(_cfbIv, _blockSize, _cfbIv, 0, _cfbIv.Length - _blockSize);
            Buffer.BlockCopy(Input, InOffset, _cfbIv, _cfbIv.Length - _blockSize, _blockSize);

            // XOR the IV with the ciphertext producing the plaintext
            for (int i = 0; i < _blockSize; i++)
                Output[OutOffset + i] = (byte)(_cfbBuffer[i] ^ Input[InOffset + i]);
        }

        /// <summary>
        /// <para>Encrypt a block of bytes. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            _blockCipher.Transform(_cfbIv, 0, _cfbBuffer, 0);

            // XOR the IV with the plaintext producing the ciphertext
            for (int i = 0; i < _blockSize; i++)
                Output[i] = (byte)(_cfbBuffer[i] ^ Input[i]);

            // change over the input block.
            Buffer.BlockCopy(_cfbIv, _blockSize, _cfbIv, 0, _cfbIv.Length - _blockSize);
            Buffer.BlockCopy(Output, 0, _cfbIv, _cfbIv.Length - _blockSize, _blockSize);
        }

        /// <summary>
        /// <para>Encrypt a block of bytes with offset parameters. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            _blockCipher.Transform(_cfbIv, 0, _cfbBuffer, 0);

            // XOR the IV with the plaintext producing the ciphertext
            for (int i = 0; i < _blockSize; i++)
                Output[OutOffset + i] = (byte)(_cfbBuffer[i] ^ Input[InOffset + i]);

            // change over the input block.
            Buffer.BlockCopy(_cfbIv, _blockSize, _cfbIv, 0, _cfbIv.Length - _blockSize);
            Buffer.BlockCopy(Output, OutOffset, _cfbIv, _cfbIv.Length - _blockSize, _blockSize);
        }

        /// <summary>
        /// <para>Transform a block of bytes. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (_isEncryption)
            {
                EncryptBlock(Input, Output);
            }
            else
            {
                if (_isParallel)
                    ParallelDecrypt(Input, Output);
                else
                    DecryptBlock(Input, Output);
            }
        }

        /// <summary>
        /// <para>Transform a block of bytes with offset parameters. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (_isEncryption)
                EncryptBlock(Input, InOffset, Output, OutOffset);
            else
            {
                if (_isParallel)
                    ParallelDecrypt(Input, InOffset, Output, OutOffset);
                else
                    DecryptBlock(Input, InOffset, Output, OutOffset);
            }
        }
        #endregion

        #region Parallel Decrypt
        private void ParallelDecrypt(byte[] Input, byte[] Output)
        {
            if (Output.Length < ParallelBlockSize)
            {
                int blocks = Output.Length / _blockSize;

                // output is input xor with random
                for (int i = 0; i < blocks; i++)
                    DecryptBlock(Input, i * _blockSize, Output, i * _blockSize);
            }
            else
            {
                // parallel CBC decryption
                int prcCount = ProcessorCount;
                int cnkSize = ParallelBlockSize / prcCount;
                int blkCount = (cnkSize / _blockSize);
                byte[][] vectors = new byte[prcCount][];

                for (int i = 0; i < prcCount; i++)
                {
                    vectors[i] = new byte[_blockSize];

                    // get the first iv
                    if (i != 0)
                        Buffer.BlockCopy(Input, (i * cnkSize) - _blockSize, vectors[i], 0, _blockSize);
                    else
                        Buffer.BlockCopy(_cfbIv, 0, vectors[i], 0, _blockSize);
                }

                System.Threading.Tasks.Parallel.For(0, prcCount, i =>
                {
                    for (int j = 0; j < blkCount; j++)
                        ProcessDecrypt(Input, (i * cnkSize) + (j * _blockSize), Output, (i * cnkSize) + (j * _blockSize), vectors[i]);
                });

                // copy the last vector to class variable
                Buffer.BlockCopy(vectors[prcCount - 1], 0, _cfbIv, 0, _cfbIv.Length);
            }
        }

        private void ParallelDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if ((Output.Length - OutOffset) < ParallelBlockSize)
            {
                int blocks = (Output.Length - OutOffset) / _blockSize;

                // output is input xor with random
                for (int i = 0; i < blocks; i++)
                    DecryptBlock(Input, (i * _blockSize) + InOffset, Output, (i * _blockSize) + OutOffset);
            }
            else
            {
                // parallel CBC decryption //
                int cnkSize = ParallelBlockSize / ProcessorCount;
                int blkCount = (cnkSize / _blockSize);
                byte[][] vectors = new byte[ProcessorCount][];

                for (int i = 0; i < ProcessorCount; i++)
                {
                    vectors[i] = new byte[_blockSize];
                    // get the first iv
                    if (i != 0)
                        Buffer.BlockCopy(Input, (InOffset + (i * cnkSize)) - _blockSize, vectors[i], 0, _blockSize);
                    else
                        Buffer.BlockCopy(_cfbIv, 0, vectors[i], 0, _blockSize);
                }

                System.Threading.Tasks.Parallel.For(0, ProcessorCount, i =>
                {
                    for (int j = 0; j < blkCount; j++)
                        ProcessDecrypt(Input, InOffset + (i * cnkSize) + (j * _blockSize), Output, OutOffset + (i * cnkSize) + (j * _blockSize), vectors[i]);
                });

                // copy the last vector to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, _cfbIv, 0, _cfbIv.Length);
            }
        }
        #endregion

        #region Private Methods
        private void ProcessDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset, byte[] Vector)
        {
            byte[] cfbBuffer = new byte[Vector.Length];

            _blockCipher.Transform(Vector, 0, cfbBuffer, 0);

            // change over the input block.
            Buffer.BlockCopy(Vector, _blockSize, Vector, 0, Vector.Length - _blockSize);
            Buffer.BlockCopy(Input, InOffset, Vector, Vector.Length - _blockSize, _blockSize);

            // XOR the IV with the ciphertext producing the plaintext
            for (int i = 0; i < _blockSize; i++)
                Output[OutOffset + i] = (byte)(cfbBuffer[i] ^ Input[InOffset + i]);
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_blockCipher != null && _disposeEngine)
                    {
                        _blockCipher.Dispose();
                        _blockCipher = null;
                    }

                    if (_cfbIv != null)
                    {
                        Array.Clear(_cfbIv, 0, _cfbIv.Length);
                        _cfbIv = null;
                    }
                    if (_cfbBuffer != null)
                    {
                        Array.Clear(_cfbBuffer, 0, _cfbBuffer.Length);
                        _cfbBuffer = null;
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
