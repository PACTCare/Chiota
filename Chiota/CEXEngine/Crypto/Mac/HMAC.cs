#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
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
// Implementation Details:
// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// HMAC: An implementation of a Hash based Message Authentication Code
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new HMAC(new SHA256Digest(), [DisposeEngine]))
    /// {
    ///     // initialize
    ///     mac.Initialize(Key, [Iv]);
    ///     // get mac
    ///     Output = mac.ComputeMac(Input);
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
    /// <item><description>Key size should be equal to digest output size: <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
    /// <item><description>Block size is the Digests engines block size.</description></item>
    /// <item><description>Digest size is the Digest engines digest return size.</description></item>
    /// <item><description>The <see cref="HMAC(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>The <see cref="ComputeMac(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
    /// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198-1</a>: The Keyed-Hash Message Authentication Code (HMAC).</description></item>
    /// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">180-4</a>: Secure Hash Standard (SHS).</description></item>
    /// <item><description>CRYPTO '06, Lecture <a href="http://cseweb.ucsd.edu/~mihir/papers/hmac-new.pdf">NMAC and HMAC Security</a>: NMAC and HMAC Security Proofs.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class HMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "HMAC";
        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;
        #endregion

        #region Fields
        private int m_blockSize;
        private int m_digestSize;
        private bool m_disposeEngine = true;
        private bool m_isDisposed = false;
        private byte[] m_inputPad;
        private bool m_isInitialized = false;
        private IDigest m_msgDigest;
        private byte[] m_outputPad;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Macs internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return m_msgDigest.BlockSize; }
        }

        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public Macs Enumeral
        {
            get { return Macs.HMAC; }
        }

        /// <summary>
        /// Get: Mac is ready to digest data
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
            private set { m_isInitialized = value; }
        }

        /// <summary>
        /// Get: Size of returned mac in bytes
        /// </summary>
        public int MacSize
        {
            get { return m_msgDigest.DigestSize; }
        }

        /// <summary>
        /// Get: Algorithm name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class using the digest enumeration name
        /// </summary>
        /// 
        /// <param name="DigestType">The message digest enumeration name</param>
        public HMAC(Digests DigestType)
        {
            IDigest digest = Helper.DigestFromName.GetInstance(DigestType);

            m_disposeEngine = true;
            m_msgDigest = digest;
            m_digestSize = digest.DigestSize;
            m_blockSize = digest.BlockSize;
            m_inputPad = new byte[m_blockSize];
            m_outputPad = new byte[m_blockSize];
        }

        /// <summary>
        /// Initialize this class using the digest enumeration name.
        /// <para>When this constructor is used, <see cref="Initialize(byte[], byte[])"/> is called automatically.</para>
        /// </summary>
        /// 
        /// <param name="DigestType">The message digest enumeration name</param>
        /// <param name="Key">HMAC Key; passed to HMAC Initialize() through constructor</param>
        public HMAC(Digests DigestType, byte[] Key)
        {
            IDigest digest = Helper.DigestFromName.GetInstance(DigestType);

            m_disposeEngine = true;
            m_msgDigest = digest;
            m_digestSize = digest.DigestSize;
            m_blockSize = digest.BlockSize;
            m_inputPad = new byte[m_blockSize];
            m_outputPad = new byte[m_blockSize];

            Initialize(Key);
        }

        /// <summary>
        /// Initialize this class class using a digest instance
        /// </summary>
        /// 
        /// <param name="Digest">The message digest instance</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null digest is used</exception>
        public HMAC(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoMacException("HMAC:Ctor", "Digest can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_msgDigest = Digest;
            m_digestSize = Digest.DigestSize;
            m_blockSize = Digest.BlockSize;
            m_inputPad = new byte[m_blockSize];
            m_outputPad = new byte[m_blockSize];
        }

        /// <summary>
        /// Initialize the class and working variables.
        /// <para>When this constructor is used, <see cref="Initialize(byte[], byte[])"/> is called automatically.</para>
        /// </summary>
        /// 
        /// <param name="Digest">The message digest instance</param>
        /// <param name="Key">HMAC Key; passed to HMAC Initialize() through constructor</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null digest is used</exception>
        public HMAC(IDigest Digest, byte[] Key, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoMacException("HMAC:Ctor", "Digest can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_msgDigest = Digest;
            m_digestSize = Digest.DigestSize;
            m_blockSize = Digest.BlockSize;
            m_inputPad = new byte[m_blockSize];
            m_outputPad = new byte[m_blockSize];

            Initialize(Key);
        }

        private HMAC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~HMAC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the digest
        /// </summary>
        /// 
        /// <param name="Input">Hash input data</param>
        /// <param name="InOffset">Starting position with the Input array</param>
        /// <param name="Length">Length of data to process</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if (InOffset + Length > Input.Length)
                throw new CryptoMacException("HMAC:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            m_msgDigest.BlockUpdate(Input, InOffset, Length);
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>HMAC hash value</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            if (!m_isInitialized)
                throw new CryptoGeneratorException("HMAC:ComputeMac", "The Mac is not initialized!", new InvalidOperationException());

            byte[] hash = new byte[m_msgDigest.DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Completes processing and returns the HMAC code
        /// </summary>
        /// 
        /// <param name="Output">Output array that receives the hash code</param>
        /// <param name="OutOffset">Offset within Output array</param>
        /// 
        /// <returns>The number of bytes processed</returns>
        /// 
        /// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < m_msgDigest.DigestSize)
                throw new CryptoMacException("HMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            byte[] temp = new byte[m_digestSize];
            m_msgDigest.DoFinal(temp, 0);
            m_msgDigest.BlockUpdate(m_outputPad, 0, m_outputPad.Length);
            m_msgDigest.BlockUpdate(temp, 0, temp.Length);
            int msgLen = m_msgDigest.DoFinal(Output, OutOffset);
            m_msgDigest.BlockUpdate(m_inputPad, 0, m_inputPad.Length);

            Reset();

            return msgLen;
        }

        /// <summary>
        /// Initialize the HMAC
        /// </summary>
        /// 
        /// <param name="MacKey">The HMAC Key. 
        /// <para>Key should be equal in size to the <see cref="MacSize"/> value.</para>
        /// </param>
        /// <param name="IV">The optional HMAC Initialization Vector. 
        /// <para>If the IV is non null, the Key and IV are concatenated and passed through the hash function to produce the HMAC Key.</para>
        /// </param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if the Key is null or less than digest size</exception>
        public void Initialize(byte[] MacKey, byte[] IV = null)
        {
            if (MacKey == null)
                throw new CryptoMacException("HMAC:Initialize", "HmacKey can not be null!", new ArgumentNullException());

            m_msgDigest.Reset();

            byte[] tmpKey = (byte[])MacKey.Clone();
            int keyLength = tmpKey.Length;

            if (IV != null) // combine and compress
            {
                tmpKey = VTDev.Libraries.CEXEngine.Utility.ArrayUtils.Concat(MacKey, IV);
                m_msgDigest.BlockUpdate(tmpKey, 0, tmpKey.Length);
                m_msgDigest.DoFinal(m_inputPad, 0);
                keyLength = m_digestSize;
            }
            else if (keyLength > m_blockSize) // compress to block size
            {
                m_msgDigest.BlockUpdate(tmpKey, 0, tmpKey.Length);
                m_msgDigest.DoFinal(m_inputPad, 0);
                keyLength = m_digestSize;
            }
            else
            {
                Array.Copy(tmpKey, 0, m_inputPad, 0, keyLength);
            }

            Array.Clear(m_inputPad, keyLength, m_blockSize - keyLength);
            Array.Copy(m_inputPad, 0, m_outputPad, 0, m_blockSize);

            XorPad(m_inputPad, IPAD);
            XorPad(m_outputPad, OPAD);

            // initialise the digest
            m_msgDigest.BlockUpdate(m_inputPad, 0, m_inputPad.Length);
            m_isInitialized = true;
        }

        /// <summary>
        /// Reset and initialize the underlying digest
        /// </summary>
        public void Reset()
        {
            m_msgDigest.Reset();
            m_msgDigest.BlockUpdate(m_inputPad, 0, m_inputPad.Length);
        }

        /// <summary>
        /// Update the digest with 1 byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            m_msgDigest.Update(Input);
        }

        #endregion

        #region Private Methods
        private static void XorPad(byte[] A, byte N)
        {
            for (int i = 0; i < A.Length; ++i)
                A[i] ^= N;
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
                    if (m_inputPad != null)
                    {
                        Array.Clear(m_inputPad, 0, m_inputPad.Length);
                        m_inputPad = null;
                    }
                    if (m_outputPad != null)
                    {
                        Array.Clear(m_outputPad, 0, m_outputPad.Length);
                        m_outputPad = null;
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
