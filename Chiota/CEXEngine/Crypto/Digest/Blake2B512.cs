#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest.Support;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
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
// Principal Algorithms:
// An implementation of Blake2, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn, and Christian Winnerlein. 
// Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.
// 
// Implementation Details:
// An implementation of the Blake2B and Blake2BP digests with a 512 bit digest output size.
// Based on the Blake2 Github projects by Samuel Neves and Christian Winnerlein.
// Blake2: https://github.com/BLAKE2/BLAKE2
//
// Written by John Underhill, July 5, 2016
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// Blake2Bp512: An implementation of the Blake2B and Blake2BP digests with a 512 bit digest output size
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using the ComputeHash method:</description>
    /// <para>Use the ComputeHash method for small to medium data sizes</para>
    /// <code>
    /// using (IDigest hash = new Blake2Bp512())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Algorithm is selected through the constructor (2B or 2BP), parallel version is selected through either the Parallel flag, or via the Blake2Params ThreadCount() configuration parameter.</description></item>
    /// <item><description>Parallel and sequential algorithms (Blake2B or Blake2BP) produce different digest outputs, this is expected.</description></item>
    /// <item><description>Sequential Block size is 128 bytes, (1024 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
    /// <item><description>Parallel Block input size to the BlockUpdate function should be aligned to a multiple of ParallelMinimumSize() for best performance.</description></item>
    /// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KiB to 25MiB.</description></item>
    /// <item><description>The number of threads used in parallel mode can be user defined through the Blake2Params->ThreadCount property to any even number of threads; note that hash output value will change with threadcount.</description></item>
    /// <item><description>Digest output size is fixed at 64 bytes, (512 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Blake2 <a href="https://blake2.net/">Homepage</a>.</description></item>
    /// <item><description>Blake2 on <a href="https://github.com/BLAKE2/BLAKE2">Github</a>.</description></item>
    /// <item><description>Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.</description></item>
    /// <item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
    /// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
    /// <item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class Blake2B512 : IDigest
    {
        #region Constants
        private const int BLOCK_SIZE = 128;
        private const int DIGEST_SIZE = 64;
        private const int CHAIN_SIZE = 8;
        private const int COUNTER_SIZE = 2;
        private const int DEF_LEAFSIZE = 1024 * 1000 * 10;
        private const int FLAG_SIZE = 2;
        private const int MAX_PRLBLOCK = 1024 * 1000 * 400;
        private const int PARALLEL_DEG = 4;
        private const int MIN_PRLBLOCK = PARALLEL_DEG * BLOCK_SIZE;
        private const int ROUND_COUNT = 12;
        private const ulong ULL_MAX = 18446744073709551615;
        private static readonly ulong[] m_cIV =
        {
            0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
            0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL

        };
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private bool m_isParallel = false;
        private int m_leafSize = DEF_LEAFSIZE;
        private byte[] m_msgBuffer = new byte[BLOCK_SIZE];
        private int m_msgLength = 0;
        private int m_parallelBlockSize = PARALLEL_DEG * DEF_LEAFSIZE;
        private Blake2bState[] m_State;
        private ulong[] m_treeConfig = new ulong[CHAIN_SIZE];
        private bool m_treeDestroy;
        private Blake2Params m_treeParams;
        private int m_minParallel = PARALLEL_DEG * BLOCK_SIZE;
        #endregion

        #region Structures
        private struct Blake2bState
        {
            internal ulong[] H;
            internal ulong[] T;
            internal ulong[] F;

            internal void Init()
            {
                H = new ulong[CHAIN_SIZE];
                T = new ulong[COUNTER_SIZE];
                F = new ulong[FLAG_SIZE];
            }

            internal void Reset()
            {
                if (H != null)
                {
                    Array.Clear(H, 0, H.Length);
                    H = null;
                }
                if (T != null)
                {
                    Array.Clear(T, 0, T.Length);
                    T = null;
                }
                if (F != null)
                {
                    Array.Clear(F, 0, F.Length);
                    F = null;
                }
            }
        };
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// Get: The digests type name
        /// </summary>
        public Digests Enumeral
        {
            get { return Digests.Blake2B512; }
        }

        /// <summary>
        /// Get: The Digest name
        /// </summary>
        public string Name
        {
            get
            {
                if (m_isParallel)
                    return "BlakeBP512";
                else
                    return "Blake2Bp512";
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class as either the 2B or 2BP variant.
        /// <para>Initialize as either the parallel version Blake2BP, or sequential Blake2B variant.</para>
        /// </summary>
        /// 
        /// <param name="Parallel">Setting the Parallel flag to true, instantiates the Blake2BP variant.</param>
        public Blake2B512(bool Parallel = false)
        {
            m_isParallel = Parallel;
            m_treeDestroy = true;

            if (m_isParallel)
            {
                m_msgBuffer = new byte[2 * PARALLEL_DEG * BLOCK_SIZE];
                m_State = new Blake2bState[PARALLEL_DEG];
                for (int i = 0; i < PARALLEL_DEG; ++i)
                    m_State[i].Init();
                // sets defaults of depth 2, fanout 4, 4 threads
                m_treeParams = new Blake2Params(64, 0, 4, 2, 0, 0, 0, 64, 4);
                // minimum block size
                m_minParallel = PARALLEL_DEG * BLOCK_SIZE;
                // default parallel input block expected is Pn * 16384 bytes
                m_parallelBlockSize = m_leafSize * PARALLEL_DEG;
                // initialize the leaf nodes 
                Reset();
            }
            else
            {
                m_State = new Blake2bState[1];
                m_State[0].Init();
                // default depth 1, fanout 1, leaf length unlimited
                m_treeParams = new Blake2Params(64, 0, 1, 1, 0, 0, 0, 0, 0);
                Initialize(m_treeParams, m_State[0]);
            }
        }

        /// <summary>
        /// Initialize the class with a Blake2Params structure.
        /// <para>The parameters structure allows for tuning of the internal configuration string,
        /// and changing the number of threads used by the parallel mechanism (ThreadCount).
        /// If the ThreadCount is greater than 1, parallel mode (Blake2BP) is instantiated.
        /// The default threadcount is 4, changing from the default will produce a different output hash code.</para>
        /// </summary>
        /// 
        /// <param name="Params">The Blake2Params structure, containing the tree configuration settings.</param>
        public Blake2B512(Blake2Params Params)
        {
            m_isParallel = m_treeParams.ThreadDepth > 1;
            m_treeParams = Params;

            if (m_isParallel)
            {
                if (Params.LeafLength != 0 && (Params.LeafLength < BLOCK_SIZE || Params.LeafLength % BLOCK_SIZE != 0))
                    throw new CryptoHashException("BlakeBP512:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
                if (Params.ThreadDepth < 2 || Params.ThreadDepth % 2 != 0)
                    throw new CryptoHashException("BlakeBP512:Ctor", "The ThreadDepth parameter is invalid! Must be an even number greater than 1.");

                m_msgBuffer = new byte[2 * Params.ThreadDepth * BLOCK_SIZE];
                m_State = new Blake2bState[Params.ThreadDepth];
                m_minParallel = m_treeParams.ThreadDepth * BLOCK_SIZE;
                m_leafSize = Params.LeafLength == 0 ? DEF_LEAFSIZE : Params.LeafLength;
                // set parallel block size as Pn * leaf size 
                m_parallelBlockSize = Params.ThreadDepth * m_leafSize;
                // initialize leafs
                Reset();
            }
            else
            {
                // fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
                m_treeParams = new Blake2Params(64, 0, 1, 1, 0, 0, 0, 0, 0);
                Initialize(m_treeParams, m_State[0]);
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Blake2B512()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoHashException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if (Length == 0)
                return;

            if (m_isParallel)
            {
                int ttlLen = Length + m_msgLength;
                int minPrl = m_msgBuffer.Length + (m_minParallel - BLOCK_SIZE);

                // input larger than min parallel; process buffer and loop-in remainder
                if (ttlLen > minPrl)
                {
                    // fill buffer
                    int rmd = m_msgBuffer.Length - m_msgLength;
                    if (rmd != 0)
                        Buffer.BlockCopy(Input, InOffset, m_msgBuffer, m_msgLength, rmd);

                    m_msgLength = 0;
                    Length -= rmd;
                    InOffset += rmd;
                    ttlLen -= m_msgBuffer.Length;

                    // empty the message buffer
                    System.Threading.Tasks.Parallel.For(0, m_treeParams.ThreadDepth, i =>
                    {
                        ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], BLOCK_SIZE);
                        ProcessBlock(m_msgBuffer, (i * BLOCK_SIZE) + (m_treeParams.ThreadDepth * BLOCK_SIZE), m_State[i], BLOCK_SIZE);
                    });

                    // loop in the remainder (no buffering)
                    if (Length > minPrl)
                    {
                        // calculate working set size
                        int prcLen = Length - m_minParallel;
                        if (prcLen % m_minParallel != 0)
                            prcLen -= (prcLen % m_minParallel);

                        // process large blocks
                        System.Threading.Tasks.Parallel.For(0, m_treeParams.ThreadDepth, i =>
                        {
                            ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_State[i], (ulong)prcLen);
                        });

                        Length -= prcLen;
                        InOffset += prcLen;
                        ttlLen -= prcLen;
                    }
                }

                // remainder exceeds buffer size; process first 4 blocks and shift buffer left
                if (ttlLen > m_msgBuffer.Length)
                {
                    // fill buffer
                    int rmd = m_msgBuffer.Length - m_msgLength;
                    if (rmd != 0)
                        Buffer.BlockCopy(Input, InOffset, m_msgBuffer, m_msgLength, rmd);

                    Length -= rmd;
                    InOffset += rmd;
                    m_msgLength = m_msgBuffer.Length;

                    // process first half of buffer
                    System.Threading.Tasks.Parallel.For(0, m_treeParams.ThreadDepth, i =>
                    {
                        ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], BLOCK_SIZE);
                    });

                    // left rotate the buffer
                    m_msgLength -= m_minParallel;
                    rmd = m_msgBuffer.Length / 2;
                    Buffer.BlockCopy(m_msgBuffer, rmd, m_msgBuffer, 0, rmd);
                }
            }
            else
            {
                if (m_msgLength + Length > BLOCK_SIZE)
                {
                    int rmd = BLOCK_SIZE - m_msgLength;
                    if (rmd != 0)
                        Buffer.BlockCopy(Input, InOffset, m_msgBuffer, m_msgLength, rmd);

                    ProcessBlock(m_msgBuffer, 0, m_State[0], BLOCK_SIZE);
                    m_msgLength = 0;
                    InOffset += rmd;
                    Length -= rmd;
                }

                // loop until last block
                while (Length > BLOCK_SIZE)
                {
                    ProcessBlock(Input, InOffset, m_State[0], BLOCK_SIZE);
                    InOffset += BLOCK_SIZE;
                    Length -= BLOCK_SIZE;
                }
            }

            // store unaligned bytes
            if (Length != 0)
            {
                Buffer.BlockCopy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
                m_msgLength += Length;
            }
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            byte[] hash = new byte[DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Do final processing and get the hash value
        /// </summary>
        /// 
        /// <param name="Output">The Hash value container</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value</returns>
        /// 
        /// <exception cref="CryptoHashException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (m_isParallel)
            {
                byte[] hashCodes = new byte[m_treeParams.ThreadDepth * DIGEST_SIZE];

                // padding
                if (m_msgLength < m_msgBuffer.Length)
                    Array.Clear(m_msgBuffer, m_msgLength, m_msgBuffer.Length - m_msgLength);

                ulong prtBlk = ULL_MAX;

                // process unaligned blocks
                if (m_msgLength > m_minParallel)
                {
                    int blkCount = (m_msgLength - m_minParallel) / BLOCK_SIZE;
                    if (m_msgLength % BLOCK_SIZE != 0)
                        ++blkCount;

                    for (int i = 0; i < blkCount; ++i)
                    {
                        // process partial block set
                        ProcessBlock(m_msgBuffer, (i * BLOCK_SIZE), m_State[i], BLOCK_SIZE);
                        Buffer.BlockCopy(m_msgBuffer, m_minParallel + (i * BLOCK_SIZE), m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
                        m_msgLength -= BLOCK_SIZE;
                    }

                    if (m_msgLength % BLOCK_SIZE != 0)
                        prtBlk = (ulong)blkCount - 1;
                }

                // process last 4 blocks
                for (int i = 0; i < m_treeParams.ThreadDepth; ++i)
                {
                    // apply f0 bit reversal constant to final blocks
                    m_State[i].F[0] = ULL_MAX;
                    int blkSze = BLOCK_SIZE;

                    // f1 constant on last block
                    if (i == m_treeParams.ThreadDepth - 1)
                        m_State[i].F[1] = ULL_MAX;

                    if (i == (int)prtBlk)
                    {
                        blkSze = m_msgLength % BLOCK_SIZE;
                        m_msgLength += BLOCK_SIZE - blkSze;
                        Array.Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkSze, BLOCK_SIZE - blkSze);
                    }
                    else if (m_msgLength < 1)
                    {
                        blkSze = 0;
                        Array.Clear(m_msgBuffer, i * BLOCK_SIZE, BLOCK_SIZE);
                    }
                    else if (m_msgLength < BLOCK_SIZE)
                    {
                        blkSze = m_msgLength;
                        Array.Clear(m_msgBuffer, (i * BLOCK_SIZE) + blkSze, BLOCK_SIZE - blkSze);
                    }

                    ProcessBlock(m_msgBuffer, i * BLOCK_SIZE, m_State[i], (ulong)blkSze);
                    m_msgLength -= BLOCK_SIZE;

                    IntUtils.Le512ToBlock(m_State[i].H, hashCodes, i * DIGEST_SIZE);
                }

                // set up the root node
                m_msgLength = 0;
                m_treeParams.NodeDepth = 1;
                m_treeParams.NodeOffset = 0;
                m_treeParams.MaxDepth = 2;
                Initialize(m_treeParams, m_State[0]);

                // load blocks
                for (int i = 0; i < m_treeParams.ThreadDepth; ++i)
                    BlockUpdate(hashCodes, i * DIGEST_SIZE, DIGEST_SIZE);

                // compress all but last block
                for (int i = 0; i < hashCodes.Length - BLOCK_SIZE; i += BLOCK_SIZE)
                    ProcessBlock(m_msgBuffer, i, m_State[0], BLOCK_SIZE);

                // apply f0 and f1 flags
                m_State[0].F[0] = ULL_MAX;
                m_State[0].F[1] = ULL_MAX;
                // last compression
                ProcessBlock(m_msgBuffer, m_msgLength - BLOCK_SIZE, m_State[0], BLOCK_SIZE);
                // output the code
                IntUtils.Le512ToBlock(m_State[0].H, Output, OutOffset);
            }
            else
            {
                int padLen = m_msgBuffer.Length - m_msgLength;
                if (padLen > 0)
                    Array.Clear(m_msgBuffer, m_msgLength, padLen);

                m_State[0].F[0] = ULL_MAX;
                ProcessBlock(m_msgBuffer, 0, m_State[0], (ulong)m_msgLength);
                IntUtils.Le512ToBlock(m_State[0].H, Output, OutOffset);
            }

            Reset();

            return DIGEST_SIZE;
        }

        /// <summary>
        /// Initialize the digest as a counter based DRBG
        /// </summary>
        /// 
        /// <param name="MacKey">The input key parameters; the input Key must be a minimum of 64 bytes</param>
        /// <param name="Output">The psuedo random output</param>
        /// 
        /// <returns>The number of bytes generated</returns>
        public int Generate(MacParams MacKey, byte[] Output)
        {
            if (Output.Length == 0)
                throw new CryptoHashException("Blake2Bp512:Generate", "Buffer size must be at least 1 byte!");
            if (MacKey.Key.Length < DIGEST_SIZE)
                throw new CryptoHashException("Blake2Bp512:Generate", "The key must be at least 64 bytes long!");

            int bufSize = DIGEST_SIZE;
            byte[] inpCtr = new byte[BLOCK_SIZE];

            // add the key to state
            LoadMacKey(MacKey);
            // process the key
            ProcessBlock(m_msgBuffer, 0, m_State[0], BLOCK_SIZE);
            // copy hash to upper half of input
            Buffer.BlockCopy(m_State[0].H, 0, inpCtr, DIGEST_SIZE, DIGEST_SIZE);
            // add padding to empty bytes; hamming const 'ipad'
            Array.Clear(inpCtr, 8, DIGEST_SIZE - 8);
            // increment the input counter
            Increment(inpCtr);
            // process the block
            ProcessBlock(inpCtr, 0, m_State[0], BLOCK_SIZE);

            if (bufSize < Output.Length)
            {
                Buffer.BlockCopy(m_State[0].H, 0, Output, 0, bufSize);
                int rmd = Output.Length - bufSize;

                while (rmd > 0)
                {
                    Buffer.BlockCopy(m_State[0].H, 0, inpCtr, DIGEST_SIZE, DIGEST_SIZE);
                    Increment(inpCtr);
                    ProcessBlock(inpCtr, 0, m_State[0], BLOCK_SIZE);

                    if (rmd > DIGEST_SIZE)
                    {
                        Buffer.BlockCopy(m_State[0].H, 0, Output, bufSize, DIGEST_SIZE);
                        bufSize += DIGEST_SIZE;
                        rmd -= DIGEST_SIZE;
                    }
                    else
                    {
                        rmd = Output.Length - bufSize;
                        Buffer.BlockCopy(m_State[0].H, 0, Output, bufSize, rmd);
                        rmd = 0;
                    }
                }
            }
            else
            {
                Buffer.BlockCopy(m_State[0].H, 0, Output, 0, Output.Length);
            }

            return Output.Length;
        }

        /// <summary>
        /// Initialize the digest as a MAC code generator
        /// </summary>
        /// 
        /// <param name="MacKey">The input key parameters. 
        /// <para>The input Key must be a maximum size of 64 bytes, and a minimum size of 32 bytes. 
        /// If either the Salt or Info parameters are used, their size must be 16 bytes.
        /// The maximum combined size of Key, Salt, and Info, must be 128 bytes or less.</para></param>
        public void LoadMacKey(MacParams MacKey)
        {
            if (MacKey.Key.Length < 32 || MacKey.Key.Length > 64)
                throw new CryptoHashException("Blake2Bp512", "Mac Key has invalid length!");

            if (MacKey.Salt != null)
            {
                if (MacKey.Salt.Length != 16)
                    throw new CryptoHashException("Blake2Bp512", "Salt has invalid length!");

                m_treeConfig[4] = IntUtils.BytesToLe64(MacKey.Salt, 0);
                m_treeConfig[5] = IntUtils.BytesToLe64(MacKey.Salt, 8);
            }

            if (MacKey.Info != null)
            {
                if (MacKey.Info.Length != 16)
                    throw new CryptoHashException("Blake2Bp512", "Info has invalid length!");

                m_treeConfig[6] = IntUtils.BytesToLe64(MacKey.Info, 0);
                m_treeConfig[7] = IntUtils.BytesToLe64(MacKey.Info, 8);
            }

            byte[] mkey = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(MacKey.Key, 0, mkey, 0, MacKey.Key.Length);
            m_treeParams.KeyLength = (byte)MacKey.Key.Length;

            if (m_isParallel)
            {
                // initialize the leaf nodes and add the key 
                for (int i = 0; i < m_treeParams.ThreadDepth; ++i)
                {
                    Buffer.BlockCopy(mkey, 0, m_msgBuffer, i * BLOCK_SIZE, mkey.Length);
                    m_treeParams.NodeOffset = i;
                    Initialize(m_treeParams, m_State[i]);
                }
                m_msgLength = m_minParallel;
                m_treeParams.NodeOffset = 0;
            }
            else
            {
                Buffer.BlockCopy(mkey, 0, m_msgBuffer, 0, mkey.Length);
                m_msgLength = BLOCK_SIZE;
                Initialize(m_treeParams, m_State[0]);
            }
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            m_msgLength = 0;
            Array.Clear(m_msgBuffer, 0, m_msgBuffer.Length);

            if (m_isParallel)
            {
                for (int i = 0; i < m_treeParams.ThreadDepth; ++i)
                {
                    m_treeParams.NodeOffset = i;
                    Initialize(m_treeParams, m_State[i]);
                }
                m_treeParams.NodeOffset = 0;
            }
            else
            {
                Initialize(m_treeParams, m_State[0]);
            }
        }

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            BlockUpdate(new byte[] { Input }, 0, 1);
        }
        #endregion

        #region Private Methods
        private void Compress(byte[] Input, int InOffset, Blake2bState State)
        {
            ulong[] msg = new ulong[16];

            msg[0] = IntUtils.BytesToLe64(Input, InOffset);
            msg[1] = IntUtils.BytesToLe64(Input, InOffset + 8);
            msg[2] = IntUtils.BytesToLe64(Input, InOffset + 16);
            msg[3] = IntUtils.BytesToLe64(Input, InOffset + 24);
            msg[4] = IntUtils.BytesToLe64(Input, InOffset + 32);
            msg[5] = IntUtils.BytesToLe64(Input, InOffset + 40);
            msg[6] = IntUtils.BytesToLe64(Input, InOffset + 48);
            msg[7] = IntUtils.BytesToLe64(Input, InOffset + 56);
            msg[8] = IntUtils.BytesToLe64(Input, InOffset + 64);
            msg[9] = IntUtils.BytesToLe64(Input, InOffset + 72);
            msg[10] = IntUtils.BytesToLe64(Input, InOffset + 80);
            msg[11] = IntUtils.BytesToLe64(Input, InOffset + 88);
            msg[12] = IntUtils.BytesToLe64(Input, InOffset + 96);
            msg[13] = IntUtils.BytesToLe64(Input, InOffset + 104);
            msg[14] = IntUtils.BytesToLe64(Input, InOffset + 112);
            msg[15] = IntUtils.BytesToLe64(Input, InOffset + 120);

            ulong v0 = State.H[0];
            ulong v1 = State.H[1];
            ulong v2 = State.H[2];
            ulong v3 = State.H[3];
            ulong v4 = State.H[4];
            ulong v5 = State.H[5];
            ulong v6 = State.H[6];
            ulong v7 = State.H[7];
            ulong v8 = m_cIV[0];
            ulong v9 = m_cIV[1];
            ulong v10 = m_cIV[2];
            ulong v11 = m_cIV[3];
            ulong v12 = m_cIV[4] ^ State.T[0];
            ulong v13 = m_cIV[5] ^ State.T[1];
            ulong v14 = m_cIV[6] ^ State.F[0];
            ulong v15 = m_cIV[7] ^ State.F[1];

            // round 0
            v0 += v4 + msg[0];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[1];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[2];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[3];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[4];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[5];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[6];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[7];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[8];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[9];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[10];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[11];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[12];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[13];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[14];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[15];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 1
            v0 += v4 + msg[14];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[10];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[4];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[8];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[9];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[15];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[13];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[6];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[1];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[12];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[0];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[2];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[11];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[7];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[5];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[3];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 2
            v0 += v4 + msg[11];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[8];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[12];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[0];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[5];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[2];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[15];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[13];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[10];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[14];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[3];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[6];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[7];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[1];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[9];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[4];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 3
            v0 += v4 + msg[7];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[9];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[3];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[1];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[13];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[12];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[11];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[14];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[2];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[6];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[5];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[10];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[4];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[0];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[15];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[8];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 4
            v0 += v4 + msg[9];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[0];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[5];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[7];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[2];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[4];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[10];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[15];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[14];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[1];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[11];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[12];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[6];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[8];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[3];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[13];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 5
            v0 += v4 + msg[2];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[12];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[6];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[10];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[0];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[11];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[8];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[3];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[4];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[13];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[7];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[5];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[15];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[14];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[1];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[9];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 6
            v0 += v4 + msg[12];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[5];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[1];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[15];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[14];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[13];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[4];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[10];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[0];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[7];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[6];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[3];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[9];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[2];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[8];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[11];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 7
            v0 += v4 + msg[13];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[11];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[7];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[14];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[12];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[1];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[3];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[9];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[5];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[0];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[15];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[4];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[8];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[6];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[2];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[10];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 8
            v0 += v4 + msg[6];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[15];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[14];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[9];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[11];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[3];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[0];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[8];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[12];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[2];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[13];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[7];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[1];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[4];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[10];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[5];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 9
            v0 += v4 + msg[10];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[2];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[8];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[4];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[7];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[6];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[1];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[5];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[15];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[11];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[9];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[14];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[3];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[12];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[13];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[0];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 10
            v0 += v4 + msg[0];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[1];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[2];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[3];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[4];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[5];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[6];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[7];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[8];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[9];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[10];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[11];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[12];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[13];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[14];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[15];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // round 11
            v0 += v4 + msg[14];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 += v4 + msg[10];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 += v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            v1 += v5 + msg[4];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 += v5 + msg[8];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 += v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v2 += v6 + msg[9];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 += v6 + msg[15];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 += v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v3 += v7 + msg[13];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 += v7 + msg[6];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 += v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v0 += v5 + msg[1];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 += v5 + msg[12];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 += v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            v1 += v6 + msg[0];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 += v6 + msg[2];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 += v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            v2 += v7 + msg[11];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 += v7 + msg[7];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 += v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            v3 += v4 + msg[5];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 += v4 + msg[3];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 += v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            State.H[0] ^= v0 ^ v8;
            State.H[1] ^= v1 ^ v9;
            State.H[2] ^= v2 ^ v10;
            State.H[3] ^= v3 ^ v11;
            State.H[4] ^= v4 ^ v12;
            State.H[5] ^= v5 ^ v13;
            State.H[6] ^= v6 ^ v14;
            State.H[7] ^= v7 ^ v15;
        }

        void Increase(Blake2bState State, ulong Length)
        {
            State.T[0] += Length;
            if (State.T[0] < Length)
                ++State.T[1];
        }

        void Increment(byte[] Counter)
        {
            IntUtils.Le64ToBytes(IntUtils.BytesToLe64(Counter, 0) + 1, Counter, 0);
        }

        void Initialize(Blake2Params Params, Blake2bState State)
        {
            Array.Clear(State.T, 0, COUNTER_SIZE);
            Array.Clear(State.F, 0, FLAG_SIZE);
            Array.Copy(m_cIV, 0, State.H, 0, CHAIN_SIZE);

            m_treeConfig[0] = Params.DigestLength;
            m_treeConfig[0] |= (ulong)Params.KeyLength << 8;
            m_treeConfig[0] |= (ulong)Params.FanOut << 16;
            m_treeConfig[0] |= (ulong)Params.MaxDepth << 24;
            m_treeConfig[0] |= (ulong)Params.LeafLength << 32;
            m_treeConfig[1] = (ulong)Params.NodeOffset;
            m_treeConfig[2] = Params.NodeDepth;
            m_treeConfig[2] |= (ulong)Params.InnerLength << 8;

            State.H[0] ^= m_treeConfig[0];
            State.H[1] ^= m_treeConfig[1];
            State.H[2] ^= m_treeConfig[2];
            State.H[3] ^= m_treeConfig[3];
            State.H[4] ^= m_treeConfig[4];
            State.H[5] ^= m_treeConfig[5];
            State.H[6] ^= m_treeConfig[6];
            State.H[7] ^= m_treeConfig[7];
        }

        void ProcessBlock(byte[] Input, int InOffset, Blake2bState State, ulong Length)
        {
            Increase(State, Length);
            Compress(Input, InOffset, State);
        }

        void ProcessLeaf(byte[] Input, int InOffset, Blake2bState State, ulong Length)
        {
            do
            {
                ProcessBlock(Input, InOffset, State, BLOCK_SIZE);
                InOffset += m_minParallel;
                Length -= (ulong)m_minParallel;
            }
            while (Length > 0);
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
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    m_isDisposed = true;
                    m_isParallel = false;
                    m_leafSize = 0;
                    m_msgLength = 0;
                    m_parallelBlockSize = 0;
                    m_minParallel = 0;
                    if (m_treeDestroy)
                        m_treeParams.Reset();
                    m_treeDestroy = false;

                    if (m_State != null)
                    {
                        for (int i = 0; i < m_State.Length; ++i)
                            m_State[i].Reset();
                    }
                    if (m_msgBuffer != null)
                    {
                        Array.Clear(m_msgBuffer, 0, m_msgBuffer.Length);
                        m_msgBuffer = null;
                    }
                    if (m_treeConfig != null)
                    {
                        Array.Clear(m_treeConfig, 0, m_treeConfig.Length);
                        m_treeConfig = null;
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
