#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Kdf;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
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
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle 
// <a href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.48/org/bouncycastle/crypto/generators/HKDFBytesGenerator.java">SHA512</a> class.
// 
// Implementation Details:
// An implementation of an Hash based Key Derivation Function (HKDF). 
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// HKDF: An implementation of an Hash based Key Derivation Function
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new HKDF(new SHA512()))
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, Ikm, [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mac.HMAC"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with a <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> or a <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Macs">Mac</see>.</description></item>
    /// <item><description>The <see cref="HKDF(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Salt size should be multiple of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc5869">5869</a>: HMAC-based Extract-and-Expand Key Derivation Function.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class HKDF : IKdf
    {
        #region Constants
        private const string ALG_NAME = "HKDF";
        #endregion

        #region Fields
        private byte[] m_currentT;
        private int m_hashSize;
        private bool m_isInitialized = false;
        private bool m_isDisposed = false;
        private byte[] m_kdfInfo = new byte[0];
        private IMac m_kdfMac;
        private bool m_disposeEngine = true;
        private int m_generatedBytes;
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
        /// Minimum recommended initialization key size in bytes.
        /// <para>Combined sizes of key, salt, and info should be at least this size.</para></para>
        /// </summary>
        public int MinKeySize
        {
            get { return m_hashSize; }
        }

        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public Kdfs Enumeral
        {
            get { return Kdfs.HKDF; }
        }

        /// <summary>
        /// Get/Set: Sets the Info value in the HKDF initialization parameters.
        /// <para>Must be set before Initialize() function is called.
        /// Code should be either a zero byte array, or a multiple of the HKDF digest engines return size.</para>
        /// </summary>
        public byte[] Info
        {
            get { return m_kdfInfo; }
            set { m_kdfInfo = value; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class using the message digests enumeration name
        /// </summary>
        /// 
        /// <param name="DigestType">The message digest enumeration name</param>
        public HKDF(Digests DigestType)
        {
            IDigest digest = Helper.DigestFromName.GetInstance(DigestType);
            m_disposeEngine = true;
            m_kdfMac = new HMAC(digest);
            m_hashSize = digest.DigestSize;
        }

        /// <summary>
        /// Initialize this class class using a Digest instance
        /// </summary>
        /// 
        /// <param name="Digest">The message digest instance</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Digest is used</exception>
        public HKDF(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("HKDF:Ctor", "Digest can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_kdfMac = new HMAC(Digest);
            m_hashSize = Digest.DigestSize;
        }

        /// <summary>
        /// Initialize this class class using an Hmac instance
        /// </summary>
        /// 
        /// <param name="Hmac">The Hmac digest instance</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Hmac is used</exception>
        public HKDF(IMac Hmac)
        {
            if (Hmac == null)
                throw new CryptoGeneratorException("HKDF:Ctor", "Hmac can not be null!", new ArgumentNullException());

            m_kdfMac = Hmac;
            m_hashSize = Hmac.MacSize;
        }

        private HKDF()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~HKDF()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
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
        /// <exception cref="CryptoGeneratorException">Thrown if the output buffer is too small, or the size requested exceeds maximum: 255 * HashLen bytes</exception>
        public int Generate(byte[] Output, int OutOffset, int Size)
        {
            if ((Output.Length - Size) < OutOffset)
                throw new CryptoGeneratorException("PBKDF2:Generate", "Output buffer too small!", new Exception());
            if (m_generatedBytes + Size > 255 * m_hashSize)
                throw new CryptoGeneratorException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output", new ArgumentOutOfRangeException());

            if (m_generatedBytes % m_hashSize == 0)
                ExpandNext();

            // copy what is left in the buffer
            int toGenerate = Size;
            int posInT = m_generatedBytes % m_hashSize;
            int leftInT = m_hashSize - m_generatedBytes % m_hashSize;
            int toCopy = System.Math.Min(leftInT, toGenerate);

            Buffer.BlockCopy(m_currentT, posInT, Output, OutOffset, toCopy);
            m_generatedBytes += toCopy;
            toGenerate -= toCopy;
            OutOffset += toCopy;

            while (toGenerate > 0) // TODO: review- this can be faster
            {
                ExpandNext();
                toCopy = System.Math.Min(m_hashSize, toGenerate);
                Buffer.BlockCopy(m_currentT, 0, Output, OutOffset, toCopy);
                m_generatedBytes += toCopy;
                toGenerate -= toCopy;
                OutOffset += toCopy;
            }

            return Size;
        }

        /// <summary>
        /// Initialize the generator with a MacParams structure containing the key, and optional salt, and info string
        /// </summary>
        /// 
        /// <param name="GenParam">The MacParams containing the generators keying material</param>
        public void Initialize(MacParams GenParam)
        {
            if (GenParam.Salt.Length != 0)
            {
                if (GenParam.Info.Length != 0)

                    Initialize(GenParam.Key, GenParam.Salt, GenParam.Info);
                else

                    Initialize(GenParam.Key, GenParam.Salt);
            }
            else
            {

                Initialize(GenParam.Key);
            }
        }

        /// <summary>
        /// Initialize the generator with a key
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null key is used</exception>
        public void Initialize(byte[] Key)
        {
            if (Key == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Key can not be null!", new ArgumentNullException());

            m_kdfMac.Initialize(Key, null);
            m_generatedBytes = 0;
            m_currentT = new byte[m_hashSize];
            m_isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator with key and salt arrays
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value containing an additional source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null key or salt is used</exception>
        public void Initialize(byte[] Key, byte[] Salt)
        {
            if (Key == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Salt can not be null!", new ArgumentNullException());

            m_kdfMac.Initialize(Extract(Key, Salt), null);
            m_generatedBytes = 0;
            m_currentT = new byte[m_hashSize];
            m_isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator with a key, a salt array, and an information string or nonce
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value used as an additional source of entropy</param>
        /// <param name="Info">The information string or nonce used as a third source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null key, salt, or info string is used</exception>
        public void Initialize(byte[] Key, byte[] Salt, byte[] Info)
        {
            if (Key == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Salt can not be null!", new ArgumentNullException());

            m_kdfMac.Initialize(Extract(Key, Salt), null);

            if (Info != null)
                m_kdfInfo = Info;

            m_generatedBytes = 0;
            m_currentT = new byte[m_hashSize];
            m_isInitialized = true;
        }

        /// <summary>
        /// Update the Seed material
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("HKDF:Update", "Seed can not be null!", new ArgumentNullException());

            Initialize(Seed);
        }
        #endregion

        #region Private Methods
        private byte[] Extract(byte[] Salt, byte[] Ikm)
        {
            byte[] prk = new byte[m_hashSize];

            if (Salt.Length == 0)
                m_kdfMac.Initialize(new byte[m_hashSize], null);
            else
                m_kdfMac.Initialize(Salt, null);

            m_kdfMac.BlockUpdate(Ikm, 0, Ikm.Length);
            m_kdfMac.DoFinal(prk, 0);

            return prk;
        }

        private void ExpandNext()
        {
            int n = m_generatedBytes / m_hashSize + 1;

            if (n >= 256)
                throw new CryptoGeneratorException("HKDF:ExpandNext", "HKDF cannot generate more than 255 blocks of HashLen size", new ArgumentOutOfRangeException());

            // special case for T(0): T(0) is empty, so no update
            if (m_generatedBytes != 0)
                m_kdfMac.BlockUpdate(m_currentT, 0, m_hashSize);
            if (m_kdfInfo.Length > 0)
                m_kdfMac.BlockUpdate(m_kdfInfo, 0, m_kdfInfo.Length);

            m_kdfMac.Update((byte)n);
            m_kdfMac.DoFinal(m_currentT, 0);
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
                    if (m_kdfMac != null && m_disposeEngine)
                    {
                        m_kdfMac.Dispose();
                        m_kdfMac = null;
                    }
                    if (m_currentT != null)
                    {
                        Array.Clear(m_currentT, 0, m_currentT.Length);
                        m_currentT = null;
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
