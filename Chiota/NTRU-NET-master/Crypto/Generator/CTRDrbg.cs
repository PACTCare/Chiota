#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
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
// An implementation of a Counter based Deterministic Random Byte Generator (CTRDRBG). 
// Written by John Underhill, November 21, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// <h3>CTRDrbg: An implementation of a Encryption Counter based Deterministic Random Byte Generator.</h3>
    /// <para>A Block Cipher Counter DRBG as outlined in NIST document: SP800-90A<cite>SP800-90B</cite></para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new CTRDrbg(new RDX()))
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, [Ikm], [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
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
    /// <item><description>Can be initialized with any block <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">cipher</see>.</description></item>
    /// <item><description>Parallelized by default on a multi processer system when an input byte array of <see cref="ParallelMinimumSize"/> bytes or larger is used.</description></item>
    /// <item><description>Parallelization can be disabled using the <see cref="IsParallel"/> property.</description></item>
    /// <item><description>The <see cref="CTRDrbg(IBlockCipher, bool, int)">Constructors</see> DisposeEngine parameter determines if Cipher engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Combination of [Salt, Ikm, Nonce] must be: cipher key size +  cipher block size in length.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
    /// <item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
    /// <item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
    /// <item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CTRDrbg : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "CTRDrbg";
        private const int BLOCK_SIZE = 16;
        private const int COUNTER_SIZE = 16;
        private const Int32 MAX_PARALLEL = 1024000;
        private const Int32 MIN_PARALLEL = 1024;
        #endregion

        #region Fields
        private int _blockSize = BLOCK_SIZE;
        private IBlockCipher _Cipher;
        private byte[] _ctrVector;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _keySize = 32 + COUNTER_SIZE;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator is ready to produce data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get/Set Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _isParallel; }
            set
            {
                if (ProcessorCount == 1)
                    _isParallel = false;
                else
                    _isParallel = value;
            }
        }

        /// <summary>
        /// <para>The key size (in bytes) of the symmetric cipher</para>
        /// </summary>
        public int KeySize
        {
            get { return _keySize; }
            private set { _keySize = value; }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public static int ParallelMaximumSize
        {
            get { return MAX_PARALLEL; }
        }

        /// <summary>
        /// Processor count
        /// </summary>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get: Algorithm Name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Minimum input size to trigger parallel processing
        /// </summary>
        public static int ParallelMinimumSize
        {
            get { return MIN_PARALLEL; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Creates a CTR Bytes Generator using a block cipher
        /// </summary>
        /// 
        /// <param name="Cipher">The block cipher</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// <param name="KeySize">The key size (in bytes) of the symmetric cipher; a <c>0</c> value will auto size the key</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null block cipher is used</exception>
        public CTRDrbg(IBlockCipher Cipher, bool DisposeEngine = true, int KeySize = 0)
        {
            if (Cipher == null)
                throw new CryptoGeneratorException("CTRDrbg:Ctor", "Cipher can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _Cipher = Cipher;

            if (KeySize > 0)
                _keySize = KeySize;
            else
                _keySize = GetKeySize();

            _blockSize = _Cipher.BlockSize;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        private CTRDrbg()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CTRDrbg()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null salt is used</exception>
        public void Initialize(byte[] Salt)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Salt.Length < _keySize + COUNTER_SIZE)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", string.Format("Minimum key size has not been added. Size must be at least {0} bytes!", _keySize + COUNTER_SIZE), new ArgumentOutOfRangeException());

            _ctrVector = new byte[_blockSize];
            Buffer.BlockCopy(Salt, 0, _ctrVector, 0, _blockSize);
            int keyLen = Salt.Length - _blockSize;
            byte[] key = new byte[keyLen];
            Buffer.BlockCopy(Salt, _blockSize, key, 0, keyLen);

            _Cipher.Initialize(true, new KeyParams(key));
            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null salt or ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Ikm == null)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", "IKM can not be null!", new ArgumentNullException());

            byte[] seed = new byte[Salt.Length + Ikm.Length];

            Buffer.BlockCopy(Salt, 0, seed, 0, Salt.Length);
            Buffer.BlockCopy(Ikm, 0, seed, Salt.Length, Ikm.Length);

            Initialize(seed);
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Info">Nonce value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null salt or ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm, byte[] Info)
        {
            byte[] seed = new byte[Salt.Length + Ikm.Length + Info.Length];

            Buffer.BlockCopy(Salt, 0, seed, 0, Salt.Length);
            Buffer.BlockCopy(Ikm, 0, seed, Salt.Length, Ikm.Length);
            Buffer.BlockCopy(Info, 0, seed, Ikm.Length + Salt.Length, Info.Length);

            Initialize(seed);
        }

        /// <summary>
        /// Generate a block of pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        public int Generate(byte[] Output)
        {
            ParallelTransform(Output, 0);

            return Output.Length;
        }

        /// <summary>
        /// Generate pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if the output buffer is too small</exception>
        public int Generate(byte[] Output, int OutOffset, int Size)
        {
            if ((Output.Length - Size) < OutOffset)
                throw new CryptoGeneratorException("CTRDrbg:Generate", "Output buffer too small!", new Exception());

            ParallelTransform(Output, OutOffset);

            return Size;
        }

        /// <summary>
        /// <para>Update the Seed material. Two state Seed paramater: 
        /// If Seed size is equal to cipher key size plus counter size, both are updated. 
        /// If Seed size is equal to counter size (16 bytes) counter is updated.</para>
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("CTRDrbg:Update", "Seed can not be null!", new ArgumentNullException());

            if (Seed.Length >= KeySize)
                Initialize(Seed);
            else if (Seed.Length >= COUNTER_SIZE)
                Buffer.BlockCopy(Seed, 0, _ctrVector, 0, _ctrVector.Length);
        }
        #endregion

        #region Random Generator
        private void ParallelTransform(byte[] Output, int OutOffset)
        {
            if (!IsParallel || Output.Length < MIN_PARALLEL)
            {
                // generate random
                byte[] rand = Transform(Output.Length, _ctrVector);
                // copy to output array
                Buffer.BlockCopy(rand, 0, Output, OutOffset, rand.Length);
            }
            else
            {
                // parallel CTR processing //
                int prcCount = ProcessorCount;
                int algSize = Output.Length / _blockSize;
                int cnkSize = (algSize / prcCount) * _blockSize;
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
                    byte[] prand = Transform(cnkSize, vectors[i]);
                    // copy to output array
                    Buffer.BlockCopy(prand, 0, Output, OutOffset + (i * cnkSize), cnkSize);
                });

                // last block processing
                if (rndSize < Output.Length)
                {
                    int fnlSize = Output.Length % rndSize;
                    byte[] prand = Transform(fnlSize, vectors[prcCount - 1]);

                    // copy to output array
                    Buffer.BlockCopy(prand, 0, Output, OutOffset + rndSize, fnlSize);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[prcCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private byte[] Transform(Int32 Size, byte[] Counter)
        {
            // align to upper divisible of block size
            int algSize = (Size % _blockSize == 0 ? Size : Size + _blockSize - (Size % _blockSize));
            int lstBlock = algSize - _blockSize;
            byte[] randBlock = new byte[_blockSize];
            byte[] outputData = new byte[Size];

            for (int i = 0; i < algSize; i += _blockSize)
            {
                // encrypt counter
                _Cipher.EncryptBlock(Counter, randBlock);

                // copy to output
                if (i != lstBlock)
                {
                    // copy transform to output
                    Buffer.BlockCopy(randBlock, 0, outputData, i, _blockSize);
                }
                else
                {
                    // copy last block
                    int fnlSize = (Size % _blockSize) == 0 ? _blockSize : (Size % _blockSize);
                    Buffer.BlockCopy(randBlock, 0, outputData, i, fnlSize);
                }

                // increment counters
                Increment(Counter);
            }

            return outputData;
        }

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

        #region Helpers
        private int GetKeySize()
        {
            switch (_Cipher.Name)
            {
                case "RHX":
                case "RSM":
                case "SHX":
                case "THX":
                case "TSM":
                    return 320;
                default:
                    return 32;
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_Cipher != null && _disposeEngine)
                    {
                        _Cipher.Dispose();
                        _Cipher = null;
                    }
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
