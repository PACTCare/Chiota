#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Digest;
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
// Code Base Guides:</description>
// Portions of this code based on the Bouncy Castle Java 
// <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.
// 
// Implementation Details:</description>
// An implementation of a Digest Counter based Deterministic Random Byte Generator (DGTDRBG),
// based on the NIST <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Hash_DRBG</see>, SP800-90A Appendix E1. 
// Written by John Underhill, January 09, 2014
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// <h3>DGTDRBG: An implementation of a Digest Counter based Deterministic Random Byte Generator.</h3>
    /// <para>A Digest Counter DRBG as outlined in NIST document: SP800-90A<cite>SP800-90A</cite></para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new DGTDRBG(new SHA512()))
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest">VTDev.Libraries.CEXEngine.Crypto.Digest Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any <see cref="Digests">digest</see>.</description></item>
    /// <item><description>Combination of [Salt, Ikm, Nonce] must be at least: digest block size + counter (8 bytes) size in length.</description></item>
    /// <item><description>The <see cref="DGCDrbg(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// <item><description>Output buffer is 4 * the digest return size.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-90A: <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Appendix E1.</see></description></item>
    /// <item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
    /// <item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
    /// <item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
    /// <item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class DGCDrbg : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "DGCDrbg";
        private const int COUNTER_SIZE = 8;
        private const long CYCLE_COUNT = 10;
        #endregion

        #region Fields
        private byte[] _dgtSeed;
        private byte[] _dgtState;
        private bool _disposeEngine = true;
        private bool _isInitialized = false;
        private int _keySize = 32 + COUNTER_SIZE;
        private bool _isDisposed = false;
        private IDigest _msgDigest;
        private long _stateCtr = 1;
        private long _seedCtr = 1;
        private object _objLock = new object();
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
        /// <para>Minimum initialization key size in bytes; 
        /// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
        /// </summary>
        public int KeySize
        {
            get { return _keySize; }
            private set { _keySize = value; }
        }

        /// <summary>
        /// Algorithm name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Digest">Hash function</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null digest is used</exception>
        public DGCDrbg(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("DGCDrbg:Ctor", "Digest can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _msgDigest = Digest;
            _dgtSeed = new byte[Digest.DigestSize];
            _dgtState = new byte[Digest.DigestSize];
            _keySize = _msgDigest.BlockSize + COUNTER_SIZE;
        }

        private DGCDrbg()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DGCDrbg()
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
                throw new CryptoGeneratorException("DGCDrbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Salt.Length < COUNTER_SIZE)
                throw new CryptoGeneratorException("DGCDrbg:Initialize", "Salt must be at least 8 bytes!", new ArgumentOutOfRangeException());

            Int64[] counter = new Int64[1];
            int keyLen = (Salt.Length - COUNTER_SIZE) < 0 ? 0 : Salt.Length - COUNTER_SIZE;
            byte[] key = new byte[keyLen];
            int ctrLen = Math.Min(COUNTER_SIZE, Salt.Length);

            Buffer.BlockCopy(Salt, 0, counter, 0, ctrLen);
            Buffer.BlockCopy(Salt, ctrLen, key, 0, keyLen);

            UpdateSeed(key);
            UpdateCounter(counter[0]);

            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null salt is used</exception>
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
        /// <param name="Info">Info value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null salt is used</exception>
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
            return Generate(Output, 0, Output.Length);
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
                throw new CryptoGeneratorException("DGCDrbg:Generate", "Output buffer too small!", new Exception());

            int offset = 0;
            int len = OutOffset + Size;

            GenerateState();

            for (int i = OutOffset; i < len; ++i)
            {
                if (offset == _dgtState.Length)
                {
                    GenerateState();
                    offset = 0;
                }

                Output[i] = _dgtState[offset++];
            }

            return Size;
        }

        /// <summary>
        /// <para>Update the Seed material. Three state Seed paramater: 
        /// If Seed size is equal to digest blocksize plus counter size, both are updated. 
        /// If Seed size is equal to digest block size, internal state seed is updated.
        /// If Seed size is equal to counter size (8 bytes) counter is updated.</para>
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null or invalid Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("DGCDrbg:Update", "Seed can not be null!", new ArgumentNullException());
            if (Seed.Length < COUNTER_SIZE)
                throw new CryptoGeneratorException("DGCDrbg:Update", String.Format("Minimum key size has not been added. Size must be at least {0} bytes!", COUNTER_SIZE), new ArgumentOutOfRangeException());

            // update seed and counter
            if (Seed.Length >= _msgDigest.BlockSize + COUNTER_SIZE)
            {
                Initialize(Seed);
            }
            else if (Seed.Length == _msgDigest.BlockSize)
            {
                UpdateSeed(Seed);
            }
            else if (Seed.Length == COUNTER_SIZE)
            {
                // update counter only
                Int64[] counter = new Int64[1];
                Buffer.BlockCopy(Seed, 0, counter, 0, COUNTER_SIZE);
                UpdateCounter(counter[0]);
            }
            else
            {
                UpdateSeed(Seed);
            }
        }
        #endregion

        #region Private Methods
        private void CycleSeed()
        {
            _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
            IncrementCounter(_seedCtr++);
            _msgDigest.DoFinal(_dgtSeed, 0);
        }

        private void IncrementCounter(long Counter)
        {
            for (int i = 0; i < 8; i++)
            {
                _msgDigest.Update((byte)Counter);
                Counter >>= 8;
            }
        }

        private void GenerateState()
        {
            lock (_objLock)
            {
                IncrementCounter(_stateCtr++);

                _msgDigest.BlockUpdate(_dgtState, 0, _dgtState.Length);
                _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
                _msgDigest.DoFinal(_dgtState, 0);

                if ((_stateCtr % CYCLE_COUNT) == 0)
                    CycleSeed();
            }
        }

        private void UpdateCounter(long Counter)
        {
            lock (_objLock)
            {
                IncrementCounter(Counter);
                _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
                _msgDigest.DoFinal(_dgtSeed, 0);
            }
        }

        private void UpdateSeed(byte[] Seed)
        {
            lock (_objLock)
            {
                _msgDigest.BlockUpdate(Seed, 0, Seed.Length);
                _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
                _msgDigest.DoFinal(_dgtSeed, 0);
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
                    if (_msgDigest != null && _disposeEngine)
                    {
                        _msgDigest.Dispose();
                        _msgDigest = null;
                    }
                    if (_dgtSeed != null)
                    {
                        Array.Clear(_dgtSeed, 0, _dgtSeed.Length);
                        _dgtSeed = null;
                    }
                    if (_dgtState != null)
                    {
                        Array.Clear(_dgtState, 0, _dgtState.Length);
                        _dgtState = null;
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
