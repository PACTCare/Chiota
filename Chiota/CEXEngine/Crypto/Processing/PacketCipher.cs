#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Helper;

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
// Written by John Underhill, May 19, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing
{
    /// <summary>
    /// PacketCipher: Performs a streaming packet cryptographic transform.
    /// <para>Wraps encryption/decryption of a byte array in a continuous operation.</para>
    /// 
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting a packet stream:</description>
    /// <code>
    /// public static void PacketCipherTest()
    /// {
    ///     const int BLSZ = 1024;
    ///     KeyParams key;
    ///     byte[] data;
    ///     MemoryStream instrm;
    ///     MemoryStream outstrm = new MemoryStream();
    /// 
    ///     using (KeyGenerator kg = new KeyGenerator())
    ///     {
    ///         // get the key
    ///         key = kg.GetKeyParams(32, 16);
    ///         // 2 * 1200 byte packets
    ///         data = kg.GetBytes(BLSZ * 2);
    ///     }
    ///     // data to encrypt
    ///     instrm = new MemoryStream(data);
    /// 
    ///     // Encrypt a stream //
    ///     // create the outbound cipher
    ///     using (ICipherMode cipher = new CTR(new RHX()))
    ///     {
    ///         // initialize the cipher for encryption
    ///         cipher.Initialize(true, key);
    ///         // set block size
    ///         ((CTR)cipher).ParallelBlockSize = BLSZ;
    /// 
    ///         // encrypt the stream
    ///         using (PacketCipher pc = new PacketCipher(cipher))
    ///         {
    ///             byte[] inbuffer = new byte[BLSZ];
    ///             byte[] outbuffer = new byte[BLSZ];
    ///             int bytesread = 0;
    /// 
    ///             while ((bytesread = instrm.Read(inbuffer, 0, BLSZ)) > 0)
    ///             {
    ///                 // encrypt the buffer
    ///                 pc.Write(inbuffer, 0, outbuffer, 0, BLSZ);
    ///                 // add it to the output stream
    ///                 outstrm.Write(outbuffer, 0, outbuffer.Length);
    ///             }
    ///         }
    ///     }
    /// 
    ///     // reset stream position
    ///     outstrm.Seek(0, SeekOrigin.Begin);
    ///     MemoryStream tmpstrm = new MemoryStream();
    /// 
    ///     // Decrypt a stream //
    ///     // create the inbound cipher
    ///     using (ICipherMode cipher = new CTR(new RHX()))
    ///     {
    ///         // initialize the cipher for decryption
    ///         cipher.Initialize(false, key);
    ///         // set block size
    ///         ((CTR)cipher).ParallelBlockSize = BLSZ;
    /// 
    ///         // decrypt the stream
    ///         using (PacketCipher pc = new PacketCipher(cipher))
    ///         {
    ///             byte[] inbuffer = new byte[BLSZ];
    ///             byte[] outbuffer = new byte[BLSZ];
    ///             int bytesread = 0;
    /// 
    ///             while ((bytesread = outstrm.Read(inbuffer, 0, BLSZ)) > 0)
    ///             {
    ///                 // process the encrypted bytes
    ///                 pc.Write(inbuffer, 0, outbuffer, 0, BLSZ);
    ///                 // write to stream
    ///                 tmpstrm.Write(outbuffer, 0, outbuffer.Length);
    ///             }
    ///         }
    ///     }
    /// 
    ///     // compare decrypted output with data
    ///     if (!Equate.AreEqual(tmpstrm.ToArray(), data))
    ///         throw new Exception();
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>This instance does not use padding; input and output arrays must be block aligned.</description></item>
    /// <item><description>Uses any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">Cipher Mode</see> wrapped <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Block Ciphers</see>, or any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher">Stream Ciphers</see>.</description></item>
    /// <item><description>Cipher Engine can be Disposed when this class is <see cref="Dispose()">Disposed</see>, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Changes to the Cipher or CipherStream <see cref="ParallelBlockSize">ParallelBlockSize</see> must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public class PacketCipher : IDisposable
    {
        #region Enums
        /// <summary>
        /// ParallelBlockProfile enumeration
        /// </summary>
        public enum BlockProfiles : int
        {
            /// <summary>
            /// Set parallel block size as a division of 100 segments
            /// </summary>
            ProgressProfile = 0,
            /// <summary>
            /// Set parallel block size for maximum possible speed
            /// </summary>
            SpeedProfile
        }
        #endregion

        #region Constants
        // Max array size allocation base; multiply by processor count for actual
        // byte/memory allocation during parallel loop execution
        private const int MAXALLOC_MB100 = 100000000;
        // default parallel block size
        private const int PARALLEL_DEFBLOCK = 64000;
        #endregion

        #region Fields
        private ICipherMode m_cipherEngine;
        private IStreamCipher m_streamCipher;
        private bool m_isEncryption = true;
        private int m_blockSize = PARALLEL_DEFBLOCK;
        private bool m_disposeEngine = false;
        private bool m_isCounterMode = false;
        private bool m_isDisposed = false;
        private bool m_isParallel = false;
        private bool m_isStreamCipher = false;
        private int m_processorCount;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return m_isParallel; }
            set { m_isParallel = value; }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
        /// or the size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return m_blockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoProcessingException("PacketCipher:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoProcessingException("PacketCipher:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

                m_blockSize = value;
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
            get
            {
                if (m_isStreamCipher)
                {
                    if (m_streamCipher.GetType().Equals(typeof(ChaCha20)))
                        return ((ChaCha20)m_streamCipher).ParallelMinimumSize;
                    else
                        return ((Salsa20)m_streamCipher).ParallelMinimumSize;
                }
                else
                {
                    if (m_cipherEngine.GetType().Equals(typeof(CTR)))
                        return ((CTR)m_cipherEngine).ParallelMinimumSize;
                    else if (m_cipherEngine.GetType().Equals(typeof(CBC)) && !m_isEncryption)
                        return ((CBC)m_cipherEngine).ParallelMinimumSize;
                    else if (m_cipherEngine.GetType().Equals(typeof(CFB)) && !m_isEncryption)
                        return ((CFB)m_cipherEngine).ParallelMinimumSize;
                    else
                        return 0;
                }
            }
        }

        /// <summary>
        /// Get: The system processor count
        /// </summary>
        public int ProcessorCount
        {
            get { return m_processorCount; }
            private set { m_processorCount = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class with a CipherDescription Structure; containing the cipher implementation details, and a <see cref="KeyParams"/> class containing the Key material.
        /// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
        /// Cipher modes, padding, and engines are destroyed automatically through this classes Dispose() method.</para>
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is an encryptor</param>
        /// <param name="Description">A <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/> containing the cipher description</param>
        /// <param name="KeyParam">A <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams"/> class containing the encryption Key material</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if an invalid CipherDescription or KeyParams is used</exception>
        public PacketCipher(bool Encryption, CipherDescription Description, KeyParams KeyParam)
        {
            if (!CipherDescription.IsValid(Description))
                throw new CryptoProcessingException("PacketCipher:CTor", "The key Header is invalid!", new ArgumentException());
            if (KeyParam == null)
                throw new CryptoProcessingException("PacketCipher:CTor", "KeyParam can not be null!", new ArgumentNullException());

            m_disposeEngine = true;
            m_isEncryption = Encryption;
            m_blockSize = Description.BlockSize;
            m_isParallel = false;

            if (m_isStreamCipher = IsStreamCipher((SymmetricEngines)Description.EngineType))
            {
                m_streamCipher = GetStreamCipher((StreamCiphers)Description.EngineType, Description.RoundCount);
                m_streamCipher.Initialize(KeyParam);

                if (m_streamCipher.GetType().Equals(typeof(ChaCha20)))
                {
                    if (m_isParallel = ((ChaCha20)m_streamCipher).IsParallel)
                        m_blockSize = ((ChaCha20)m_streamCipher).ParallelBlockSize;
                }
                else
                {
                    if (m_isParallel = ((Salsa20)m_streamCipher).IsParallel)
                        m_blockSize = ((Salsa20)m_streamCipher).ParallelBlockSize;
                }
            }
            else
            {
                m_cipherEngine = GetCipherMode((CipherModes)Description.CipherType, (BlockCiphers)Description.EngineType, Description.BlockSize, Description.RoundCount, (Digests)Description.KdfEngine);
                m_cipherEngine.Initialize(m_isEncryption, KeyParam);

                if (m_isCounterMode = m_cipherEngine.GetType().Equals(typeof(CTR)))
                {
                    if (m_isParallel = ((CTR)m_cipherEngine).IsParallel)
                        m_blockSize = ((CTR)m_cipherEngine).ParallelBlockSize;
                }
                else
                {
                    if (m_cipherEngine.GetType().Equals(typeof(CBC)))
                    {
                        if (m_isParallel = ((CBC)m_cipherEngine).IsParallel && !((CBC)m_cipherEngine).IsEncryption)
                            m_blockSize = ((CBC)m_cipherEngine).ParallelBlockSize;
                    }
                    else if (m_cipherEngine.GetType().Equals(typeof(CFB)))
                    {
                        if (m_isParallel = ((CFB)m_cipherEngine).IsParallel && !((CFB)m_cipherEngine).IsEncryption)
                            m_blockSize = ((CFB)m_cipherEngine).ParallelBlockSize;
                    }
                }
            }
        }

        /// <summary>
        /// Initialize the class with a Block <see cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">Cipher</see> and optional <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding.IPadding">Padding</see> instances.
        /// <para>This constructor requires a fully initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">CipherMode</see> instance.
        /// If the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">PaddingMode</see> parameter is null, X9.23 padding will be used if required.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Block Cipher</see> wrapped in a Cipher mode</param>
        /// <param name="Padding">The Padding instance</param>
        /// <param name="DisposeEngine">Dispose of cipher engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a null or uninitialized Cipher is used</exception>
        public PacketCipher(ICipherMode Cipher, IPadding Padding = null, bool DisposeEngine = false)
        {
            if (Cipher == null)
                throw new CryptoProcessingException("PacketCipher:CTor", "The Cipher can not be null!", new ArgumentNullException());
            if (!Cipher.IsInitialized)
                throw new CryptoProcessingException("PacketCipher:CTor", "The Cipher has not been initialized!", new ArgumentException());

            m_disposeEngine = DisposeEngine;
            m_cipherEngine = Cipher;
            m_isStreamCipher = false;
            m_blockSize = m_cipherEngine.BlockSize;
            m_isEncryption = m_cipherEngine.IsEncryption;
            m_isParallel = false;

            if (m_isCounterMode = m_cipherEngine.GetType().Equals(typeof(CTR)))
            {
                if (m_isParallel = ((CTR)m_cipherEngine).IsParallel)
                    m_blockSize = ((CTR)m_cipherEngine).ParallelBlockSize;
            }
            else
            {
                if (m_cipherEngine.GetType().Equals(typeof(CBC)))
                    m_isParallel = ((CBC)m_cipherEngine).IsParallel && !((CBC)m_cipherEngine).IsEncryption;
            }
        }

        /// <summary>
        /// Initialize the class with a <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher">Stream Cipher</see> instance.
        /// <para>This constructor requires a fully initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">CipherStream</see> instance.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The initialized Stream Cipher instance</param>
        /// <param name="DisposeEngine">Dispose of cipher engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a null or uninitialized Cipher is used</exception>
        public PacketCipher(IStreamCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoProcessingException("PacketCipher:CTor", "The Cipher can not be null!", new ArgumentNullException());
            if (!Cipher.IsInitialized)
                throw new CryptoProcessingException("PacketCipher:CTor", "The Cipher has not been initialized!", new ArgumentException());

            m_disposeEngine = DisposeEngine;
            m_streamCipher = Cipher;
            m_isStreamCipher = true;
            m_blockSize = 1024;
            m_isCounterMode = false;

            // set defaults
            if (m_streamCipher.GetType().Equals(typeof(ChaCha20)))
            {
                if (m_isParallel = ((ChaCha20)m_streamCipher).IsParallel)
                    m_blockSize = ((ChaCha20)m_streamCipher).ParallelBlockSize;
            }
            else
            {
                if (m_isParallel = ((Salsa20)m_streamCipher).IsParallel)
                    m_blockSize = ((Salsa20)m_streamCipher).ParallelBlockSize;
            }
        }

        private PacketCipher()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PacketCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Process a length within the Input stream using Offsets
        /// </summary>
        /// 
        /// <param name="Input">The Input Stream</param>
        /// <param name="InOffset">The Input Stream positional offset</param>
        /// <param name="Output">The Output Stream</param>
        /// <param name="OutOffset">The Output Stream positional offset</param>
        /// <param name="Length">The number of bytes to process</param>
        public void Write(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length)
        {
            if (!m_isStreamCipher)
            {
                if (m_isEncryption)
                    Encrypt(Input, InOffset, Output, OutOffset, Length);
                else
                    Decrypt(Input, InOffset, Output, OutOffset, Length);
            }
            else
            {
                ProcessStream(Input, InOffset, Output, OutOffset, Length);
            }
        }
        #endregion

        #region Crypto
        private void Decrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length)
        {
            // no padding, input lengths must align
            Length += InOffset;

            while (InOffset < Length)
            {
                m_cipherEngine.Transform(Input, InOffset, Output, OutOffset);
                InOffset += m_blockSize;
                OutOffset += m_blockSize;
            }
        }

        private void Encrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length)
        {
            // no padding, input lengths must align
            Length += InOffset;

            while (InOffset < Length)
            {
                m_cipherEngine.Transform(Input, InOffset, Output, OutOffset);
                InOffset += m_blockSize;
                OutOffset += m_blockSize;
            }
        }

        private IBlockCipher GetBlockCipher(BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
        {
            try
            {
                return BlockCipherFromName.GetInstance(EngineType, BlockSize, RoundCount, KdfEngine);
            }
            catch (Exception Ex)
            {
                throw new CryptoRandomException("CTRPrng:GetCipher", "The cipher could not be initialized!", Ex);
            }
        }

        private ICipherMode GetCipherMode(CipherModes CipherType, BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
        {
            IBlockCipher engine = GetBlockCipher(EngineType, BlockSize, RoundCount, KdfEngine);

            try
            {
                return CipherModeFromName.GetInstance(CipherType, engine);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetCipherMode", ex);
            }
        }

        private IPadding GetPaddingMode(PaddingModes PaddingType)
        {
            try
            {
                return PaddingFromName.GetInstance(PaddingType);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetPaddingMode", ex);
            }
        }

        private IStreamCipher GetStreamCipher(StreamCiphers EngineType, int RoundCount)
        {
            try
            {
                return StreamCipherFromName.GetInstance(EngineType, RoundCount);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetStreamEngine", ex);
            }
        }

        private bool IsStreamCipher(SymmetricEngines EngineType)
        {
            return EngineType == SymmetricEngines.ChaCha ||
                EngineType == SymmetricEngines.Salsa;
        }

        private void ProcessStream(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length)
        {
            Length += InOffset;

            while (InOffset < Length)
            {
                m_streamCipher.Transform(Input, InOffset, Output, OutOffset);
                InOffset += m_blockSize;
                OutOffset += m_blockSize;
            }
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
                    if (m_disposeEngine)
                    {
                        if (m_cipherEngine != null)
                        {
                            m_cipherEngine.Dispose();
                            m_cipherEngine = null;
                        }
                        if (m_streamCipher != null)
                        {
                            m_streamCipher.Dispose();
                            m_streamCipher = null;
                        }
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
