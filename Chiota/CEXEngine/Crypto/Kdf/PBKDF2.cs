#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Kdf;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// PBKDF2 V2: An implementation of an Hash based Key Derivation Function
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new PBKDF2(new SHA512(), 10000))
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
    /// <item><description>The <see cref="PBKDF2(IDigest, int, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Salt size should be multiple of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>RFC 2898: <a href="http://tools.ietf.org/html/rfc2898">Specification</a>.</description></item>
    /// </list>
    /// </remarks>
    public class PBKDF2 : IKdf
    {
        #region Constants
        private const string ALG_NAME = "PBKDF2";
        private const uint MIN_PASSLENGTH = 4;
        private const uint MIN_SALTLENGTH = 4;
        #endregion

        #region Fields
        private bool m_disposeEngine = true;
        private int m_hashSize;
        private bool m_isInitialized = false;
        private bool m_isDisposed = false;
        private int m_kdfIterations = 1;
        private byte[] m_kdfKey = null;
        private IMac m_kdfMac;
        private byte[] m_kdfSalt = null;
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
            get { return Kdfs.PBKDF2; }
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
        /// Creates a PBKDF2 Bytes Generator using the default SHA512 HMAC engine
        /// </summary>
        /// 
        /// <param name="Iterations">The number of cycles used to produce output</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid Iterations count is used</exception>
        public PBKDF2(int Iterations)
        {
            if (Iterations < 1)
                throw new CryptoGeneratorException("PBKDF2:Ctor", "Iterations count can not be less than 1!", new ArgumentException());

            m_kdfIterations = Iterations;
            m_disposeEngine = true;
            m_kdfMac = new HMAC(new SHA512());
            m_hashSize = m_kdfMac.MacSize;
        }

        /// <summary>
        /// Creates a PBKDF2 Bytes Generator based on the given hash function
        /// </summary>
        /// 
        /// <param name="Digest">The digest used</param>
        /// <param name="Iterations">The number of cycles used to produce output</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Digest or Iterations count is used</exception>
        public PBKDF2(IDigest Digest, int Iterations, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("PBKDF2:Ctor", "Digest can not be null!", new ArgumentNullException());
            if (Iterations < 1)
                throw new CryptoGeneratorException("PBKDF2:Ctor", "Iterations count can not be less than 1!", new ArgumentException());

            m_kdfIterations = Iterations;
            m_disposeEngine = DisposeEngine;
            m_kdfMac = new HMAC(Digest);
            m_hashSize = Digest.DigestSize;
        }

        /// <summary>
        /// Creates a PBKDF2 Bytes Generator based on the given HMAC function
        /// </summary>
        /// 
        /// <param name="Hmac">The HMAC digest used</param>
        /// <param name="Iterations">The number of cycles used to produce output</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Hmac or invalid Iterations count is used</exception>
        public PBKDF2(IMac Hmac, int Iterations, bool DisposeEngine = true)
        {
            if (Hmac == null)
                throw new CryptoGeneratorException("PBKDF2:Ctor", "Hmac can not be null!", new ArgumentNullException());
            if (Iterations < 1)
                throw new CryptoGeneratorException("PBKDF2:Ctor", "Iterations count can not be less than 1!", new ArgumentException());

            m_kdfIterations = Iterations;
            m_disposeEngine = DisposeEngine;
            m_kdfMac = Hmac;
            m_hashSize = Hmac.MacSize;
        }

        private PBKDF2()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PBKDF2()
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
        /// Initialize the generator with a passphrase.
        /// <para>The use of a salt value mitigates some attacks against a passphrase, and is highly recommended with PBKDF2.</para>
        /// </summary>
        /// 
        /// <param name="Key">The primary key (password) array used to seed the generator.
        /// <para>The minimum passphrase size is 4 bytes.</para></param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt is used</exception>
        public void Initialize(byte[] Key)
        {
            if (Key == null)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Key.Length < MIN_PASSLENGTH)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Key value is too small!", new ArgumentException());

            m_kdfKey = new byte[Key.Length];
            Buffer.BlockCopy(Key, 0, m_kdfKey, 0, m_kdfKey.Length);

            m_isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator with key and salt arrays
        /// </summary>
        /// 
        /// <param name="Key">The primary key (password) array used to seed the generator</param>
        /// <param name="Salt">The salt value containing an additional source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null key or salt is used</exception>
        public void Initialize(byte[] Key, byte[] Salt)
        {
            if (Key == null)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Salt.Length < MIN_SALTLENGTH)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Salt value is too small!", new ArgumentException());

            m_kdfKey = (byte[])Key.Clone();
            m_kdfSalt = (byte[])Salt.Clone();
            m_isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator with a key, a salt array, and an information string or nonce
        /// </summary>
        /// 
        /// <param name="Key">The primary key (password) array used to seed the generator</param>
        /// <param name="Salt">The salt value used as an additional source of entropy</param>
        /// <param name="Info">The information string or nonce used as a third source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null key, salt, or info string is used</exception>
        public void Initialize(byte[] Key, byte[] Salt, byte[] Info)
        {
            if (Key == null)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoGeneratorException("PBKDF2:Initialize", "Salt can not be null!", new ArgumentNullException());

            m_kdfKey = (byte[])Key.Clone();
            m_kdfSalt = new byte[Salt.Length + Info.Length];
            Buffer.BlockCopy(Salt, 0, m_kdfSalt, 0, Salt.Length);
            Buffer.BlockCopy(Info, 0, m_kdfSalt, Salt.Length, Info.Length);
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
            if (!m_isInitialized)
                throw new CryptoGeneratorException("PBKDF2:Generate", "The Generator is not initialized!", new InvalidOperationException());

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
                throw new CryptoGeneratorException("PBKDF2:Generate", "Output buffer too small!", new ArgumentException());
            if (!m_isInitialized)
                throw new CryptoGeneratorException("PBKDF2:Generate", "The Generator is not initialized!", new InvalidOperationException());

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
                throw new CryptoGeneratorException("PBKDF2:Update", "Seed can not be null!", new ArgumentNullException());
            if (!m_isInitialized)
                throw new CryptoGeneratorException("PBKDF2:Generate", "The Generator is not initialized!", new InvalidOperationException());

            Initialize(Seed);
        }
        #endregion

        #region Private Methods
        private int GenerateKey(byte[] Output, int OutOffset, int Size)
        {
            int hashLen = m_kdfMac.MacSize;
            int diff = Size % hashLen;
            int max = Size / hashLen;
            int ctr = 0;
            byte[] buffer = new byte[4];
            byte[] outBytes = new byte[Size];

            for (ctr = 0; ctr < max; ctr++)
            {
                IntToOctet(buffer, ctr + 1);
                Process(buffer, outBytes, ctr * hashLen);
            }

            if (diff > 0)
            {
                IntToOctet(buffer, ctr + 1);
                byte[] rem = new byte[hashLen];
                Process(buffer, rem, 0);
                Buffer.BlockCopy(rem, 0, outBytes, outBytes.Length - diff, diff);
            }

            Buffer.BlockCopy(outBytes, 0, Output, OutOffset, outBytes.Length);
            return Size;
        }

        private void IntToOctet(byte[] Output, int Counter)
        {
            Output[0] = (byte)((uint)Counter >> 24);
            Output[1] = (byte)((uint)Counter >> 16);
            Output[2] = (byte)((uint)Counter >> 8);
            Output[3] = (byte)Counter;
        }

        private void Process(byte[] Input, byte[] Output, int OutOffset)
        {
            byte[] state = new byte[m_kdfMac.MacSize];

            m_kdfMac.Initialize(m_kdfKey, null);

            if (m_kdfSalt != null)
                m_kdfMac.BlockUpdate(m_kdfSalt, 0, m_kdfSalt.Length);

            m_kdfMac.BlockUpdate(Input, 0, Input.Length);
            m_kdfMac.DoFinal(state, 0);

            Array.Copy(state, 0, Output, OutOffset, state.Length);

            for (int count = 1; count != m_kdfIterations; count++)
            {
                m_kdfMac.Initialize(m_kdfKey, null);
                m_kdfMac.BlockUpdate(state, 0, state.Length);
                m_kdfMac.DoFinal(state, 0);

                for (int j = 0; j != state.Length; j++)
                    Output[OutOffset + j] ^= state[j];
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
                    if (m_kdfMac != null && m_disposeEngine)
                    {
                        m_kdfMac.Dispose();
                        m_kdfMac = null;
                    }
                    if (m_kdfKey != null)
                    {
                        Array.Clear(m_kdfKey, 0, m_kdfKey.Length);
                        m_kdfKey = null;
                    }
                    if (m_kdfSalt != null)
                    {
                        Array.Clear(m_kdfSalt, 0, m_kdfSalt.Length);
                        m_kdfSalt = null;
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

