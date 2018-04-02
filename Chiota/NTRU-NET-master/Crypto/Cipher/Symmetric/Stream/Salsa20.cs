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
// Principal Algorithms:
// Portions of this cipher based on the Salsa20 stream cipher designed by Daniel J. Bernstein:
// Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.
// 
// Implementation Details:
// Salsa20+
// An implementation based on the Salsa20 stream cipher,
// using an higher variable rounds assignment.
// Valid Key sizes are 128, and 256 (16 and 32 bytes).
// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
// Written by John Underhill, October 17, 2014
// contact: develop@vtdev.com</para>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream
{
    /// <summary>
    /// <h3>Salsa20+: A parallelized Salsa20 stream cipher implementation.</h3>
    /// <para>A Salsa20 cipher extended to use up to 30 rounds of diffusion.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IStreamCipher</c> interface:</description>
    /// <code>
    /// using (IStreamCipher cipher = new Salsa20())
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/14" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Secondary release; updates to layout and documentation</revision>
    /// <revision date="2015/06/14" version="1.4.0.0">Added parallel processing</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.</description></item>
    /// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/design.pdf">Design</see>.</description></item>
    /// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/security.pdf">Security</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Salsa20 : IStreamCipher
    {
        #region Constants
        private const string ALG_NAME = "Salsa20";
        private const int ROUNDS20 = 20;
        private const int MAX_ROUNDS = 30;
        private const int MIN_ROUNDS = 8;
        private const int STATE_SIZE = 16;
        private const int VECTOR_SIZE = 8;
        private const int BLOCK_SIZE = 64;
        private const int PARALLEL_CHUNK = 1024;
        private const int MAXALLOC_MB100 = 100000000;
        private const int PARALLEL_DEFBLOCK = 64000;
        #endregion

        #region Fields
        private int[] _ctrVector = new int[2];
        private byte[] _ftSigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private byte[] _ftTau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _parallelBlockSize = PARALLEL_DEFBLOCK;
        private int _rndCount = ROUNDS20;
        private int[] _wrkState = new int[14];
        #endregion

        #region Properties
        /// <summary>
        /// Get the current counter value
        /// </summary>
        public long Counter
        {
            get { return ((long)_ctrVector[1] << 32) | (_ctrVector[0] & 0xffffffffL); }
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
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public static int[] LegalKeySizes
        {
            get { return new int[] { 16, 32 }; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static int[] LegalRounds
        {
            get { return new int[] { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 }; }
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
            get { return _parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoSymmetricException("Salsa20:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoSymmetricException("Salsa20:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

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
            get { return ProcessorCount * (STATE_SIZE * 4); }
        }

        /// <remarks>
        /// Get: Processor count
        /// </remarks>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get: Number of rounds
        /// </summary>
        public int Rounds
        {
            get { return _rndCount; }
            private set { _rndCount = value; }
        }

        /// <summary>
        /// Get: Initialization vector size
        /// </summary>
        public int VectorSize
        {
            get { return VECTOR_SIZE; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 20 rounds.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public Salsa20(int Rounds = ROUNDS20)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new CryptoSymmetricException("Salsa20:Ctor", "Rounds must be a positive even number!", new ArgumentOutOfRangeException());
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new CryptoSymmetricException("Salsa20:Ctor", String.Format("Rounds must be between {0} and {1)!", MIN_ROUNDS, MAX_ROUNDS), new ArgumentOutOfRangeException());

            _rndCount = Rounds;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Salsa20()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="KeyParam">Cipher key container. 
        /// <para>Uses the Key and IV fields of KeyParam. 
        /// The <see cref="LegalKeySizes"/> property contains valid Key sizes. 
        /// IV must be 8 bytes in size.</para>
        /// </param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key or iv  is used</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key or iv size  is used</exception>
        public void Initialize(KeyParams KeyParam)
        {
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("Salsa20:Initialize", "Init parameters must include an IV!", new ArgumentException());
            if (KeyParam.IV.Length != 8)
                throw new CryptoSymmetricException("Salsa20:Initialize", "Requires exactly 8 bytes of IV!", new ArgumentOutOfRangeException());

            Reset();

            if (KeyParam.Key == null)
            {
                if (!_isInitialized)
                    throw new CryptoSymmetricException("ChaCha:Initialize", "Key can not be null for first initialisation!", new ArgumentException());

                SetKey(null, KeyParam.IV);
            }
            else
            {
                if (KeyParam.Key.Length != 16 && KeyParam.Key.Length != 32)
                    throw new CryptoSymmetricException("ChaCha:Initialize", "Key must be 16 or 32 bytes!", new ArgumentOutOfRangeException());

                SetKey(KeyParam.Key, KeyParam.IV);
            }

            _isInitialized = true;
        }

        /// <summary>
        /// Reset the primary internal counter
        /// </summary>
        public void Reset()
        {
            _ctrVector[0] = _ctrVector[1] = 0;
        }

        /// <summary>
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            ProcessBlock(Input, Output);
        }

        /// <summary>
        /// Encrypt/Decrypt an array of bytes with offset parameters.
        /// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
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

        /// <summary>
        /// Encrypt/Decrypt an array of bytes with offset and length parameters.
        /// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Length">Number of bytes to process</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, int Length, byte[] Output, int OutOffset)
        {
            ProcessBlock(Input, InOffset, Length, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private void SetKey(byte[] Key, byte[] Iv)
        {
            if (Key != null)
            {
                if (Key.Length == 32)
                {
                    _wrkState[0] = Convert8To32(_ftSigma, 0);
                    _wrkState[1] = Convert8To32(Key, 0);
                    _wrkState[2] = Convert8To32(Key, 4);
                    _wrkState[3] = Convert8To32(Key, 8);
                    _wrkState[4] = Convert8To32(Key, 12);
                    _wrkState[5] = Convert8To32(_ftSigma, 4);
                    _wrkState[6] = Convert8To32(Iv, 0);
                    _wrkState[7] = Convert8To32(Iv, 4);
                    _wrkState[8] = Convert8To32(_ftSigma, 8);
                    _wrkState[9] = Convert8To32(Key, 16);
                    _wrkState[10] = Convert8To32(Key, 20);
                    _wrkState[11] = Convert8To32(Key, 24);
                    _wrkState[12] = Convert8To32(Key, 28);
                    _wrkState[13] = Convert8To32(_ftSigma, 12);
                }
                else
                {
                    _wrkState[0] = Convert8To32(_ftTau, 0);
                    _wrkState[1] = Convert8To32(Key, 0);
                    _wrkState[2] = Convert8To32(Key, 4);
                    _wrkState[3] = Convert8To32(Key, 8);
                    _wrkState[4] = Convert8To32(Key, 12);
                    _wrkState[5] = Convert8To32(_ftTau, 4);
                    _wrkState[6] = Convert8To32(Iv, 0);
                    _wrkState[7] = Convert8To32(Iv, 4);
                    _wrkState[8] = Convert8To32(_ftTau, 8);
                    _wrkState[9] = Convert8To32(Key, 0);
                    _wrkState[10] = Convert8To32(Key, 4);
                    _wrkState[11] = Convert8To32(Key, 8);
                    _wrkState[12] = Convert8To32(Key, 12);
                    _wrkState[13] = Convert8To32(_ftTau, 12);
                }
            }
        }
        #endregion

        #region Transform
        private void SalsaCore(int[] Output, int[] Counter)
        {
            int ctr = 0;

            int X0 = _wrkState[ctr++];
            int X1 = _wrkState[ctr++];
            int X2 = _wrkState[ctr++];
            int X3 = _wrkState[ctr++];
            int X4 = _wrkState[ctr++];
            int X5 = _wrkState[ctr++];
            int X6 = _wrkState[ctr++];
            int X7 = _wrkState[ctr++];
            int X8 = Counter[0];
            int X9 = Counter[1];
            int X10 = _wrkState[ctr++];
            int X11 = _wrkState[ctr++];
            int X12 = _wrkState[ctr++];
            int X13 = _wrkState[ctr++];
            int X14 = _wrkState[ctr++];
            int X15 = _wrkState[ctr];

            ctr = Rounds;

            while (ctr > 0)
            {
                // round 1
                X4 ^= Rtl(X0 + X12, 7);
                X8 ^= Rtl(X4 + X0, 9);
                X12 ^= Rtl(X8 + X4, 13);
                X0 ^= Rtl(X12 + X8, 18);
                X9 ^= Rtl(X5 + X1, 7);
                X13 ^= Rtl(X9 + X5, 9);
                X1 ^= Rtl(X13 + X9, 13);
                X5 ^= Rtl(X1 + X13, 18);
                X14 ^= Rtl(X10 + X6, 7);
                X2 ^= Rtl(X14 + X10, 9);
                X6 ^= Rtl(X2 + X14, 13);
                X10 ^= Rtl(X6 + X2, 18);
                X3 ^= Rtl(X15 + X11, 7);
                X7 ^= Rtl(X3 + X15, 9);
                X11 ^= Rtl(X7 + X3, 13);
                X15 ^= Rtl(X11 + X7, 18);
                // round 2
                X1 ^= Rtl(X0 + X3, 7);
                X2 ^= Rtl(X1 + X0, 9);
                X3 ^= Rtl(X2 + X1, 13);
                X0 ^= Rtl(X3 + X2, 18);
                X6 ^= Rtl(X5 + X4, 7);
                X7 ^= Rtl(X6 + X5, 9);
                X4 ^= Rtl(X7 + X6, 13);
                X5 ^= Rtl(X4 + X7, 18);
                X11 ^= Rtl(X10 + X9, 7);
                X8 ^= Rtl(X11 + X10, 9);
                X9 ^= Rtl(X8 + X11, 13);
                X10 ^= Rtl(X9 + X8, 18);
                X12 ^= Rtl(X15 + X14, 7);
                X13 ^= Rtl(X12 + X15, 9);
                X14 ^= Rtl(X13 + X12, 13);
                X15 ^= Rtl(X14 + X13, 18);

                ctr -= 2;
            }

            ctr = 0;
            Output[ctr] = X0 + _wrkState[ctr++];
            Output[ctr] = X1 + _wrkState[ctr++];
            Output[ctr] = X2 + _wrkState[ctr++];
            Output[ctr] = X3 + _wrkState[ctr++];
            Output[ctr] = X4 + _wrkState[ctr++];
            Output[ctr] = X5 + _wrkState[ctr++];
            Output[ctr] = X6 + _wrkState[ctr++];
            Output[ctr] = X7 + _wrkState[ctr++];
            Output[ctr] = X8 + Counter[0];
            Output[ctr + 1] = X9 + Counter[1];
            Output[ctr + 2] = X10 + _wrkState[ctr++];
            Output[ctr + 2] = X11 + _wrkState[ctr++];
            Output[ctr + 2] = X12 + _wrkState[ctr++];
            Output[ctr + 2] = X13 + _wrkState[ctr++];
            Output[ctr + 2] = X14 + _wrkState[ctr++];
            Output[ctr + 2] = X15 + _wrkState[ctr];
        }

        private byte[] Generate(int Size, int[] Counter)
        {
            // align to upper divisible of block size
            int algSize = (Size % BLOCK_SIZE == 0 ? Size : Size + BLOCK_SIZE - (Size % BLOCK_SIZE));
            int lstBlock = algSize - BLOCK_SIZE;
            int[] outputBlock = new int[STATE_SIZE];
            byte[] outputData = new byte[Size];

            for (int i = 0; i < algSize; i += BLOCK_SIZE)
            {
                SalsaCore(outputBlock, Counter);

                // copy to output
                if (i != lstBlock)
                {
                    // copy transform to output
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, BLOCK_SIZE);
                }
                else
                {
                    // copy last block
                    int fnlSize = (Size % BLOCK_SIZE) == 0 ? BLOCK_SIZE : (Size % BLOCK_SIZE);
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, fnlSize);
                }

                // increment counter
                Increment(Counter);
            }

            return outputData;
        }

        private void ProcessBlock(byte[] Input, byte[] Output)
        {
            if (!IsParallel || Output.Length < ParallelBlockSize)
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
                int alnSize = Output.Length / BLOCK_SIZE;
                int cnkSize = (alnSize / prcCount) * BLOCK_SIZE;
                int rndSize = cnkSize * prcCount;
                int subSize = (cnkSize / BLOCK_SIZE);

                // create jagged array of 'sub counters'
                int[][] vectors = new int[prcCount][];

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

            if (!IsParallel)
            {
                blkSize = blkSize < BLOCK_SIZE ? blkSize : BLOCK_SIZE;
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
                int alnSize = ParallelBlockSize / BLOCK_SIZE;
                int cnkSize = (alnSize / prcCount) * BLOCK_SIZE;
                int rndSize = cnkSize * prcCount;
                int subSize = (cnkSize / BLOCK_SIZE);

                // create jagged array of 'sub counters'
                int[][] vectors = new int[prcCount][];

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
                if (rndSize < Output.Length)
                {
                    int fnlSize = _parallelBlockSize % rndSize;
                    byte[] rand = Generate(fnlSize, vectors[prcCount - 1]);

                    for (int i = 0; i < fnlSize; i++)
                        Output[i + OutOffset + rndSize] = (byte)(Input[i + InOffset + rndSize] ^ rand[i]);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[prcCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private void ProcessBlock(byte[] Input, int InOffset, int Length, byte[] Output, int OutOffset)
        {
            int blkSize = Length;

            if (!IsParallel)
            {
                blkSize = blkSize < BLOCK_SIZE ? blkSize : BLOCK_SIZE;
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
                int alnSize = ParallelBlockSize / BLOCK_SIZE;
                int cnkSize = (alnSize / prcCount) * BLOCK_SIZE;
                int rndSize = cnkSize * prcCount;
                int subSize = (cnkSize / BLOCK_SIZE);

                // create jagged array of 'sub counters'
                int[][] vectors = new int[prcCount][];

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
                if (rndSize < Length)
                {
                    int fnlSize = _parallelBlockSize % rndSize;
                    byte[] rand = Generate(fnlSize, vectors[prcCount - 1]);

                    for (int i = 0; i < fnlSize; i++)
                        Output[i + OutOffset + rndSize] = (byte)(Input[i + InOffset + rndSize] ^ rand[i]);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[prcCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }
        #endregion

        #region Helpers
        private static byte[] Convert32ToBytes(int Input, byte[] Output, int OutOffset)
        {
            Output[OutOffset] = (byte)Input;
            Output[OutOffset + 1] = (byte)(Input >> 8);
            Output[OutOffset + 2] = (byte)(Input >> 16);
            Output[OutOffset + 3] = (byte)(Input >> 24);
            return Output;
        }

        private static void Convert32ToBytes(int[] Input, byte[] Output, int OutOffset)
        {
            for (int i = 0; i < Input.Length; ++i)
            {
                Convert32ToBytes(Input[i], Output, OutOffset);
                OutOffset += 4;
            }
        }

        private static int Convert8To32(byte[] Input, int InOffset)
        {
            return ((Input[InOffset] & 255)) |
                   ((Input[InOffset + 1] & 255) << 8) |
                   ((Input[InOffset + 2] & 255) << 16) |
                   (Input[InOffset + 3] << 24);
        }

        private void Increment(int[] Counter)
        {
            if (++Counter[0] == 0)
                ++Counter[1];
        }

        private int[] Increase(int[] Counter, int Size)
        {
            int[] copy = new int[Counter.Length];
            Array.Copy(Counter, 0, copy, 0, Counter.Length);

            for (int i = 0; i < Size; i++)
                Increment(copy);

            return copy;
        }

        private static int Rtl(int X, int Y)
        {
            // rotate left
            return (X << Y) | ((int)((uint)X >> -Y));
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
                    if (_ctrVector != null)
                    {
                        Array.Clear(_ctrVector, 0, _ctrVector.Length);
                        _ctrVector = null;
                    }
                    if (_wrkState != null)
                    {
                        Array.Clear(_wrkState, 0, _wrkState.Length);
                        _wrkState = null;
                    }
                    if (_ftTau != null)
                    {
                        Array.Clear(_ftTau, 0, _ftTau.Length);
                        _ftTau = null;
                    }
                    if (_ftSigma != null)
                    {
                        Array.Clear(_ftSigma, 0, _ftSigma.Length);
                        _ftSigma = null;
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
