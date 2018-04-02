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
// An implementation of an segmented Counter Mode (CTR).
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// <h3>Implements a Parallel Segmented Counter Mode: CTR.</h3>
    /// <para>CTR as outlined in the NIST document: SP800-38A<cite>SP800-38A</cite></para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new RDX(), [DisposeEngine]))
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
    /// <revision date="2014/11/11" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Changes to formatting and documentation</revision>
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
    /// <item><description>Parallel processing is enabled by passing a block size of <see cref="ParallelBlockSize"/> to the transform.</description></item>
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
    public sealed class CTR : ICipherMode
    {
        #region Constants
        private const string ALG_NAME = "CTR";
        private const Int32 BLOCK_SIZE = 1024;
        private const int MAXALLOC_MB100 = 100000000;
        private const Int32 PARALLEL_DEFBLOCK = 64000;
        #endregion

        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private byte[] _ctrVector;
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
        /// Get: The current state of the initialization Vector
        /// </summary>
        public byte[] IV
        {
            get { return (byte[])_ctrVector.Clone(); }
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
        /// Get: Processor count
        /// </remarks>
        private int ProcessorCount { get; set; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Cipher is used</exception>
        public CTR(IBlockCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoSymmetricException("CTR:CTor", "The Cipher can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _blockCipher = Cipher;
            _blockSize = _blockCipher.BlockSize;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        private CTR()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CTR()
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
        /// <param name="KeyParam">The KeyParams containing key and vector</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Key or IV is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("CTR:Initialize", "Key can not be null!", new ArgumentNullException());
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("CTR:Initialize", "IV can not be null!", new ArgumentNullException());

            _blockCipher.Initialize(true, KeyParam);
            _ctrVector = KeyParam.IV;
            _isEncryption = Encryption;
            _isInitialized = true;
        }

        /// <summary>
        /// <para>Transform a block of bytes. Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            ProcessBlock(Input, Output);
        }

        /// <summary>
        /// <para>Transform a block of bytes with offset parameters.  Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            ProcessBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Parallel Methods
        private byte[] Generate(Int32 Size, byte[] Counter)
        {
            // align to upper divisible of block size
            Int32 algSize = (Size % _blockSize == 0 ? Size : Size + _blockSize - (Size % _blockSize));
            Int32 lstBlock = algSize - _blockSize;
            byte[] outputBlock = new byte[_blockSize];
            byte[] outputData = new byte[Size];

            for (int i = 0; i < algSize; i += _blockSize)
            {
                // encrypt counter1 (aes: data, output, key)
                _blockCipher.EncryptBlock(Counter, outputBlock);

                // copy to output
                if (i != lstBlock)
                {
                    // copy transform to output
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, _blockSize);
                }
                else
                {
                    // copy last block
                    int fnlSize = (Size % _blockSize) == 0 ? _blockSize : (Size % _blockSize);
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, fnlSize);
                }

                // increment counter
                Increment(Counter);
            }

            return outputData;
        }

        private void ProcessBlock(byte[] Input, byte[] Output)
        {
            if (!IsParallel || Output.Length < _parallelBlockSize)
            {
                // generate random
                byte[] rand = Generate(Output.Length, _ctrVector);

                // output is input xor with random
                for (int i = 0; i < Output.Length; i++)
                    Output[i] = (byte)(Input[i] ^ rand[i]);
            }
            else
            {
                // parallel CTR processing //
                int prcCount = ProcessorCount;
                int alnSize = Output.Length / _blockSize;
                int cnkSize = (alnSize / prcCount) * _blockSize;
                int rndSize = cnkSize * prcCount;
                int subSize = (cnkSize / _blockSize);

                // create jagged array of 'sub counters'
                byte[][] vectors = new byte[prcCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, prcCount, i =>
                {
                    // offset counter by chunk size / block size
                    vectors[i] = Increase(_ctrVector, subSize * i);
                    // create random with offset counter
                    byte[] rand = Generate(cnkSize, vectors[i]);

                    // xor with input at offset
                    for (int j = 0; j < cnkSize; j++)
                        Output[j + (i * cnkSize)] = (byte)(Input[j + (i * cnkSize)] ^ rand[j]);
                });
                // last block processing
                if (rndSize < Output.Length)
                {
                    int fnlSize = Output.Length % rndSize;
                    byte[] rand = Generate(fnlSize, vectors[prcCount - 1]);

                    for (int i = 0; i < fnlSize; i++)
                        Output[i + rndSize] = (byte)(Input[i + rndSize] ^ rand[i]);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[prcCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int blkSize = (Output.Length - OutOffset);

            if (!_isParallel)
            {
                blkSize = blkSize < _blockSize ? blkSize : _blockSize;
                // generate random
                byte[] rand = Generate(blkSize, _ctrVector);

                // output is input xor with random
                for (int i = 0; i < blkSize; i++)
                    Output[i + OutOffset] = (byte)(Input[i + InOffset] ^ rand[i]);
            }
            else if (blkSize < ParallelBlockSize)
            {
                // generate random
                byte[] rand = Generate(blkSize, _ctrVector);

                // output is input xor with random
                for (int i = 0; i < blkSize; i++)
                    Output[i + OutOffset] = (byte)(Input[i + InOffset] ^ rand[i]);
            }
            else
            {
                // parallel CTR processing //
                int prcCount = ProcessorCount;
                int alnSize = ParallelBlockSize / _blockSize;
                int cnkSize = (alnSize / prcCount) * _blockSize;
                int rndSize = cnkSize * prcCount;
                int subSize = (cnkSize / _blockSize);

                // create jagged array of 'sub counters'
                byte[][] vectors = new byte[prcCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, prcCount, i =>
                {
                    // offset counter by chunk size / block size
                    vectors[i] = Increase(_ctrVector, subSize * i);
                    // create random with offset counter
                    byte[] rand = Generate(cnkSize, vectors[i]);

                    // xor with input at offset
                    for (int j = 0; j < cnkSize; j++)
                        Output[j + OutOffset + (i * cnkSize)] = (byte)(Input[j + InOffset + (i * cnkSize)] ^ rand[j]);
                });

                // last block processing
                if (rndSize < _parallelBlockSize)
                {
                    int fnlSize = ParallelBlockSize % rndSize;
                    byte[] rand = Generate(fnlSize, vectors[prcCount - 1]);

                    for (int i = 0; i < fnlSize; i++)
                        Output[i + OutOffset + rndSize] = (byte)(Input[i + InOffset + rndSize] ^ rand[i]);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[prcCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }
        #endregion

        #region Private Methods
        private static void Increment(byte[] Counter)
        {
            int i = Counter.Length;
            while (--i >= 0 && ++Counter[i] == 0) { }
        }

        private static byte[] Increase(byte[] Counter, int Size)
        {
            int carry = 0;
            byte[] buffer = new byte[Counter.Length];
            int offset = buffer.Length - 1;
            byte[] cnt = BitConverter.GetBytes(Size);
            byte osrc, odst, ndst;

            Buffer.BlockCopy(Counter, 0, buffer, 0, Counter.Length);

            for (int i = offset; i > 0; i--)
            {
                odst = buffer[i];
                osrc = offset - i < cnt.Length ? cnt[offset - i] : (byte)0;
                ndst = (byte)(odst + osrc + carry);
                carry = ndst < odst ? 1 : 0;
                buffer[i] = ndst;
            }

            return buffer;
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
                        _blockCipher.Dispose();

                    if (_ctrVector != null)
                    {
                        Array.Clear(_ctrVector, 0, _ctrVector.Length);
                        _ctrVector = null;
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
