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
// Implementation Details:
// An implementation of a Counter based Deterministic Random Byte Generator (CTRDRBG). 
// Written by John Underhill, November 21, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// <h3>SP20Drbg: A parallelized Salsa20 deterministic random byte generator implementation.</h3>
    /// <para>A Salsa20 key stream, parallelized and extended to use up to 30 rounds of diffusion.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new SP20Drbg())
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
    /// <revision date="2015/06/14" version="1.4.0.0">Initial release</revision>
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
    public sealed class SP20Drbg : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "SP20Drbg";
        private const int DEFAULT_ROUNDS = 20;
        private const int MAX_ROUNDS = 30;
        private const int MIN_ROUNDS = 8;
        private const int STATE_SIZE = 16;
        private const int VECTOR_SIZE = 8;
        private const int BLOCK_SIZE = 64;
        private const int PARALLEL_CHUNK = 1024;
        private const int MAXALLOC_MB100 = 100000000;
        private const int PARALLEL_DEFBLOCK = 64000;
        private const int MAX_PARALLEL = 1024000;
        private const int MIN_PARALLEL = 1024;
        #endregion

        #region Fields
        private int[] _ctrVector = new int[2];
        private byte[] _ftSigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private byte[] _ftTau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _parallelBlockSize = PARALLEL_DEFBLOCK;
        private int _rndCount = DEFAULT_ROUNDS;
        private int[] _wrkState = new int[14];
        private int _keySize = 32;
        #endregion

        #region Properties
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
        /// <para>The key size (in bytes) of the symmetric cipher</para>
        /// </summary>
        public int KeySize
        {
            get { return _keySize; }
            private set { _keySize = value; }
        }

        /// <summary>
        /// Get: Available Seed Sizes in bytes
        /// </summary>
        public static int[] LegalSeedSizes
        {
            get { return new int[] { 32, 48 }; }
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
        /// <exception cref="System.ArgumentException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if parallel block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoGeneratorException("SP20Drbg:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoGeneratorException("SP20Drbg:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

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
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid rounds count is chosen</exception>
        public SP20Drbg(int Rounds = 20)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new CryptoGeneratorException("SP20Drbg:Ctor", "Rounds must be a positive, even number!", new ArgumentOutOfRangeException());
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new CryptoGeneratorException("SP20Drbg:Ctor", String.Format("Rounds must be between {0} and {1}!", MIN_ROUNDS, MAX_ROUNDS), new ArgumentOutOfRangeException());

            _rndCount = Rounds;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        private SP20Drbg()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SP20Drbg()
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
        /// <exception cref="CryptoGeneratorException">Thrown if a null or invalid salt is used</exception>
        public void Initialize(byte[] Salt)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("SP20Drbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Salt.Length != LegalSeedSizes[0] && Salt.Length != LegalSeedSizes[1])
                throw new CryptoGeneratorException("SP20Drbg:Initialize", String.Format("Invalid seed size has been added. Size must be at least {0} or {1} bytes!", LegalSeedSizes[0], LegalSeedSizes[1]), new ArgumentOutOfRangeException());

            _keySize = Salt.Length;
            _ctrVector = new int[2];
            byte[] iv = new byte[16];

            Buffer.BlockCopy(Salt, 0, iv, 0, 16);
            int keyLen = Salt.Length - 16;
            byte[] key = new byte[keyLen];
            Buffer.BlockCopy(Salt, 16, key, 0, keyLen);

            SetKey(key, iv);
            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null salt or ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm)
        {
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
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null salt or ikm is used</exception>
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
            ProcessBlock(Output, 0);

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
                throw new CryptoGeneratorException("SP20Drbg:Generate", "Output buffer too small!", new Exception());

            ProcessBlock(Output, OutOffset);

            return Size;
        }

        /// <summary>
        /// <para>Update the Seed material. Two state Seed paramater: 
        /// If Seed size is equal to cipher key size plus iv size, both are updated. 
        /// If Seed size is equal to counter size (8 bytes) counter is updated.</para>
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("SP20Drbg:Update", "Seed can not be null!", new ArgumentNullException());

            if (Seed.Length >= 32)
                Initialize(Seed);
            else if (Seed.Length >= 8)
                Buffer.BlockCopy(Seed, 0, _ctrVector, 0, 8);
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

        private void ProcessBlock(byte[] Output, int OutOffset)
        {
            if (!IsParallel || Output.Length < MIN_PARALLEL)
            {
                // generate random
                byte[] rand = Generate(Output.Length, _ctrVector);
                // copy to output array
                Buffer.BlockCopy(rand, 0, Output, OutOffset, rand.Length);
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
                    Buffer.BlockCopy(rand, 0, Output, OutOffset + (i * cnkSize), cnkSize);
                });

                // last block processing
                if (rndSize < Output.Length)
                {
                    int fnlSize = Output.Length % rndSize;
                    byte[] rand = Generate(fnlSize, vectors[prcCount - 1]);
                    Buffer.BlockCopy(rand, 0, Output, OutOffset + rndSize, fnlSize);
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
