#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Drbg;
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
// Implementation Details:</description>
// An implementation of a Digest Counter based psudo random byte Generator (DGC),
// based on the NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Hash_DRBG Appendix E1</a>, SP800-90A. 
// Written by John Underhill, January 09, 2014
// Updated October 10, 2016
// Contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// An implementation of a Digest Counter based psudo random byte Generator (DGC)
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">digest</see>.</description></item>
    /// <item><description>Combination of [Salt, Ikm, Nonce] must be at least: digest block size + counter (8 bytes) size in length.</description></item>
    /// <item><description>The <see cref="DGC(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// <item><description>Output buffer is 4 * the digest return size.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">SP800-90A R1</a>: Appendix E1.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">SP800-90A</a>: Appendix E1.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class DGC : IDrbg
    {
        #region Constants
        private const string ALG_NAME = "DGCDrbg";
        private const int COUNTER_SIZE = 8;
        private const long CYCLE_COUNT = 10;
        #endregion

        #region Fields
        private byte[] m_dgtSeed;
        private byte[] m_dgtState;
        private bool m_disposeEngine = true;
        private bool m_isInitialized = false;
        private int m_keySize = 32 + COUNTER_SIZE;
        private bool m_isDisposed = false;
        private IDigest m_msgDigest;
        private long m_stateCtr = 1;
        private long m_seedCtr = 1;
        private object m_objLock = new object();
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator is ready to produce data
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
            private set { m_isInitialized = value; }
        }

        /// <summary>
        /// <para>Minimum initialization key size in bytes; 
        /// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
        /// </summary>
        public int MinSeedSize
        {
            get { return m_keySize; }
            private set { m_keySize = value; }
        }

        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public Drbgs Enumeral
        {
            get { return Drbgs.DGC; }
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
        public DGC(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("DGCDrbg:Ctor", "Digest can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_msgDigest = Digest;
            m_dgtSeed = new byte[Digest.DigestSize];
            m_dgtState = new byte[Digest.DigestSize];
            m_keySize = m_msgDigest.BlockSize + COUNTER_SIZE;
        }

        private DGC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DGC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the generator with a MacParams structure containing the key, and optional salt, and info string
        /// </summary>
        /// 
        /// <param name="GenParam">The RngParams containing the generators keying material</param>
        public void Initialize(RngParams GenParam)
        {
            if (GenParam.Nonce.Length != 0)
            {
                if (GenParam.Info.Length != 0)

                    Initialize(GenParam.Seed, GenParam.Nonce, GenParam.Info);
                else

                    Initialize(GenParam.Seed, GenParam.Nonce);
            }
            else
            {

                Initialize(GenParam.Seed);
            }
        }

        /// <summary>
        /// Initialize the generator with a seed key
        /// </summary>
        /// 
        /// <param name="Seed">The primary key array used to seed the generator</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null key is used</exception>
        public void Initialize(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("DGCDrbg:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Seed.Length < COUNTER_SIZE)
                throw new CryptoGeneratorException("DGCDrbg:Initialize", "Key must be at least 8 bytes!", new ArgumentOutOfRangeException());

            long[] counter = new long[1];
            int keyLen = (Seed.Length - COUNTER_SIZE) < 0 ? 0 : Seed.Length - COUNTER_SIZE;
            byte[] key = new byte[keyLen];
            int ctrLen = Math.Min(COUNTER_SIZE, Seed.Length);

            Buffer.BlockCopy(Seed, 0, counter, 0, ctrLen);
            Buffer.BlockCopy(Seed, ctrLen, key, 0, keyLen);

            UpdateSeed(key);
            UpdateCounter(counter[0]);

            m_isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator with seed and nonce arrays
        /// </summary>
        /// 
        /// <param name="Seed">The primary key array used to seed the generator</param>
        /// <param name="Nonce">The nonce value containing an additional source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null seed or nonce is used</exception>
        public void Initialize(byte[] Seed, byte[] Nonce)
        {
            byte[] seed = new byte[Seed.Length + Nonce.Length];

            Buffer.BlockCopy(Seed, 0, seed, 0, Seed.Length);
            Buffer.BlockCopy(Nonce, 0, seed, Seed.Length, Nonce.Length);

            Initialize(seed);
        }

        /// <summary>
        /// Initialize the generator with a seed, a nonce array, and an information string
        /// </summary>
        /// 
        /// <param name="Seed">The primary key array used to seed the generator</param>
        /// <param name="Nonce">The nonce value used as an additional source of entropy</param>
        /// <param name="Info">The information string or nonce used as a third source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null seed, nonce, or info string is used</exception>
        public void Initialize(byte[] Seed, byte[] Nonce, byte[] Info)
        {
            byte[] seed = new byte[Seed.Length + Nonce.Length + Info.Length];

            Buffer.BlockCopy(Seed, 0, seed, 0, Seed.Length);
            Buffer.BlockCopy(Nonce, 0, seed, Seed.Length, Nonce.Length);
            Buffer.BlockCopy(Info, 0, seed, Nonce.Length + Seed.Length, Info.Length);

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
                if (offset == m_dgtState.Length)
                {
                    GenerateState();
                    offset = 0;
                }

                Output[i] = m_dgtState[offset++];
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
            if (Seed.Length >= m_msgDigest.BlockSize + COUNTER_SIZE)
            {
                Initialize(Seed);
            }
            else if (Seed.Length == m_msgDigest.BlockSize)
            {
                UpdateSeed(Seed);
            }
            else if (Seed.Length == COUNTER_SIZE)
            {
                // update counter only
                long[] counter = new long[1];
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
            m_msgDigest.BlockUpdate(m_dgtSeed, 0, m_dgtSeed.Length);
            IncrementCounter(m_seedCtr++);
            m_msgDigest.DoFinal(m_dgtSeed, 0);
        }

        private void IncrementCounter(long Counter)
        {
            for (int i = 0; i < 8; i++)
            {
                m_msgDigest.Update((byte)Counter);
                Counter >>= 8;
            }
        }

        private void GenerateState()
        {
            lock (m_objLock)
            {
                IncrementCounter(m_stateCtr++);

                m_msgDigest.BlockUpdate(m_dgtState, 0, m_dgtState.Length);
                m_msgDigest.BlockUpdate(m_dgtSeed, 0, m_dgtSeed.Length);
                m_msgDigest.DoFinal(m_dgtState, 0);

                if ((m_stateCtr % CYCLE_COUNT) == 0)
                    CycleSeed();
            }
        }

        private void UpdateCounter(long Counter)
        {
            lock (m_objLock)
            {
                IncrementCounter(Counter);
                m_msgDigest.BlockUpdate(m_dgtSeed, 0, m_dgtSeed.Length);
                m_msgDigest.DoFinal(m_dgtSeed, 0);
            }
        }

        private void UpdateSeed(byte[] Seed)
        {
            lock (m_objLock)
            {
                m_msgDigest.BlockUpdate(Seed, 0, Seed.Length);
                m_msgDigest.BlockUpdate(m_dgtSeed, 0, m_dgtSeed.Length);
                m_msgDigest.DoFinal(m_dgtSeed, 0);
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
                    if (m_msgDigest != null && m_disposeEngine)
                    {
                        m_msgDigest.Dispose();
                        m_msgDigest = null;
                    }
                    if (m_dgtSeed != null)
                    {
                        Array.Clear(m_dgtSeed, 0, m_dgtSeed.Length);
                        m_dgtSeed = null;
                    }
                    if (m_dgtState != null)
                    {
                        Array.Clear(m_dgtState, 0, m_dgtState.Length);
                        m_dgtState = null;
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
