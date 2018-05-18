#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Kdf;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// KDF2Drbg: An implementation of an Hash based Key Derivation Function
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new KDF2Drbg(new SHA512()))
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with a <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> or a <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Macs">Mac</see>.</description></item>
    /// <item><description>The <see cref="KDF2(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Salt size should be multiple of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="table">
    /// <item><description>RFC 2898: <a href="http://tools.ietf.org/html/rfc2898">Password-Based Cryptography Specification Version 2.0</a>.</description></item>
    /// </list>
    /// </remarks>
    public class KDF2 : IKdf
    {
        #region Constants
        private const string ALG_NAME = "KDF2Drbg";
        #endregion

        #region Fields
        private IDigest m_digest;
        private byte[] m_Key;
        private byte[] m_Salt;
        private bool m_disposeEngine = true;
        private int m_hashSize;
        private bool m_isInitialized = false;
        private int m_blockSize = 64;
        private bool m_isDisposed = false;
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
            get { return Kdfs.KDF2; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Creates a KDF2 Bytes Generator based on the given HMAC function using the default SHA512 engine
        /// </summary>
        public KDF2()
        {
            m_disposeEngine = true;
            m_digest = new SHA512();
            m_hashSize = m_digest.DigestSize;
            m_blockSize = m_digest.BlockSize;
        }

        /// <summary>
        /// Creates a KDF2 Bytes Generator based on the given hash function
        /// </summary>
        /// 
        /// <param name="Digest">The digest used</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Digest is used</exception>
        public KDF2(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("KDF2Drbg:Ctor", "Digest can not be null!", new ArgumentNullException());

            m_disposeEngine = DisposeEngine;
            m_digest = Digest;
            m_hashSize = Digest.DigestSize;
            m_blockSize = Digest.BlockSize;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~KDF2()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
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
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Key can not be null!", new ArgumentNullException());

            if (Key.Length < m_blockSize + m_hashSize)
            {
                m_Key = new byte[Key.Length];
                // interpret as ISO18033, no IV
                Buffer.BlockCopy(Key, 0, m_Key, 0, Key.Length);
            }
            else
            {
                byte[] keyBytes = new byte[m_digest.DigestSize];
                m_Key = new byte[Key.Length - m_digest.DigestSize];
                Buffer.BlockCopy(Key, 0, m_Key, 0, Key.Length - m_digest.DigestSize);
                Buffer.BlockCopy(Key, m_Key.Length, keyBytes, 0, m_digest.DigestSize);

                m_Salt = keyBytes;
            }
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
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Key.Length < m_digest.BlockSize)
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Salt can not be less than digest blocksize!", new ArgumentException());
            if (Salt == null)
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Ikm can not be null!", new ArgumentNullException());

            m_Key = (byte[])Key.Clone();
            m_Salt = (byte[])Salt.Clone();

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
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Ikm can not be null!", new ArgumentNullException());
            if (Key.Length < m_digest.BlockSize)
                throw new CryptoGeneratorException("KDF2Drbg:Initialize", "Salt can not be less than digest blocksize!", new ArgumentException());

            m_Salt = (byte[])Salt.Clone();
            m_Key = new byte[Key.Length + Info.Length];
            Buffer.BlockCopy(Key, 0, m_Key, 0, Key.Length);
            Buffer.BlockCopy(Info, 0, m_Key, Key.Length, Info.Length);

            m_isInitialized = true;
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
            return GenerateKey(Output, 0, Output.Length);
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
                throw new CryptoGeneratorException("KDF2Drbg:Generate", "Output buffer too small!", new Exception());

            return GenerateKey(Output, OutOffset, Size);
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
                throw new CryptoGeneratorException("KDF2Drbg:Update", "Seed can not be null!", new ArgumentNullException());

            Initialize(Seed);
        }
        #endregion

        #region Private Methods
        private int GenerateKey(byte[] Output, int OutOffset, int Size)
        {
            int outLen = m_digest.DigestSize;
            int maxCtr = (int)((Size + outLen - 1) / outLen);
            // only difference between v1 & v2
            int counter = 1;
            byte[] hash = new byte[m_digest.DigestSize];

            for (int i = 0; i < maxCtr; i++)
            {
                m_digest.BlockUpdate(m_Key, 0, m_Key.Length);
                m_digest.Update((byte)(counter >> 24));
                m_digest.Update((byte)(counter >> 16));
                m_digest.Update((byte)(counter >> 8));
                m_digest.Update((byte)counter);

                if (m_Salt != null)
                    m_digest.BlockUpdate(m_Salt, 0, m_Salt.Length);

                m_digest.DoFinal(hash, 0);

                if (Size > outLen)
                {
                    Array.Copy(hash, 0, Output, OutOffset, outLen);
                    OutOffset += outLen;
                    Size -= outLen;
                }
                else
                {
                    Array.Copy(hash, 0, Output, OutOffset, Size);
                }

                counter++;
            }

            m_digest.Reset();

            return Size;
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
                    if (m_digest != null && m_disposeEngine)
                    {
                        m_digest.Dispose();
                        m_digest = null;
                    }
                    if (m_Salt != null)
                    {
                        Array.Clear(m_Salt, 0, m_Salt.Length);
                        m_Salt = null;
                    }
                    if (m_Key != null)
                    {
                        Array.Clear(m_Key, 0, m_Key.Length);
                        m_Key = null;
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
