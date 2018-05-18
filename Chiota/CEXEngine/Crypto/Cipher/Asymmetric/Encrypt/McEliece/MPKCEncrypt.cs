#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// A McEliece CCA2 Secure asymmetric cipher implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting an array:</description>
    /// <code>
    /// MPKCParameters ps = MPKCParamSets.MPKCFM11T40S256;
    /// MPKCKeyGenerator gen = new MPKCKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// 
    /// byte[] data = new byte[48];
    /// byte[] enc, dec;
    /// 
    /// // encrypt an array
    /// using (MPKCEncrypt cipher = new MPKCEncrypt(ps))
    /// {
    ///     cipher.Initialize(kp.PublicKey);
    ///     enc = cipher.Encrypt(data);
    /// }
    /// 
    /// // decrypt the cipher text
    /// using (MPKCEncrypt cipher = new MPKCEncrypt(ps))
    /// {
    ///     cipher.Initialize(kp.PrivateKey);
    ///     dec = cipher.Decrypt(enc);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.AsymmetricEngines"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Uses the McEliece CCA2 variants; Fujisaki, KobriImai, or PointCheval ciphers.</description></item>
    /// <item><description>Use the MaxPlainText property to get max input size post initialization.</description></item>
    /// <item><description>The MaxCipherText property gives the max allowable ciphertext size post initialization.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: <a href="http://cacr.uwaterloo.ca/hac/about/chap8.pdf">Chapter 8</a></description></item>
    /// <item><description>Selecting Parameters for <a href="https://eprint.iacr.org/2010/271.pdf">Secure McEliece-based Cryptosystems</a></description></item>
    /// <item><description>Weak keys in the <a href="http://perso.univ-rennes1.fr/pierre.loidreau/articles/ieee-it/Cles_Faibles.pdf">McEliece Public-Key Crypto System</a></description></item>
    /// <item><description><a href="http://binary.cr.yp.to/mcbits-20130616.pdf">McBits</a>: fast constant-time code-based cryptography: </description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> versions McEliece implementation.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCEncrypt : IAsymmetricCipher
    {
        #region Constants
        private const string ALG_NAME = "MPKCEncrypt";
        #endregion

        #region Fields
        private IMPKCCiphers m_encEngine;
        private bool m_isDisposed = false;
        private bool m_isEncryption = false;
        private bool m_isInitialized = false;
        private int m_maxPlainText;
        private int m_maxCipherText;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The cipher is initialized for encryption
        /// </summary>
        public bool IsEncryption
        {
            get
            {
                if (!m_isInitialized)
                    throw new CryptoAsymmetricException("MPKCEncrypt:IsEncryption", "The cipher must be initialized before state can be determined!", new InvalidOperationException());

                return m_isEncryption;
            }
        }

        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public int MaxCipherText
        {
            get
            {
                if (m_maxCipherText == 0 || !m_isInitialized)
                    throw new CryptoAsymmetricException("MPKCEncrypt:MaxCipherText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return m_maxCipherText;
            }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public int MaxPlainText
        {
            get
            {
                if (m_maxPlainText == 0 || !m_isInitialized)
                    throw new CryptoAsymmetricException("MPKCEncrypt:MaxPlainText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return m_maxPlainText;
            }
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
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher engine</param>
        public MPKCEncrypt(MPKCParameters CipherParams)
        {
            m_encEngine = GetEngine(CipherParams);
        }

        private MPKCEncrypt()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCEncrypt()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public byte[] Decrypt(byte[] Input)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCEncrypt:Decrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (m_isEncryption)
                throw new CryptoAsymmetricException("MPKCEncrypt:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            return m_encEngine.Decrypt(Input);
        }

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized, or the input text is invalid</exception>
        public byte[] Encrypt(byte[] Input)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCEncrypt:Encrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (Input.Length > m_maxPlainText)
                throw new CryptoAsymmetricException("MPKCEncrypt:Encrypt", "The input text is too long!", new ArgumentException());
            if (!m_isEncryption)
                throw new CryptoAsymmetricException("MPKCEncrypt:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            return m_encEngine.Encrypt(Input);
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <param name="Key">The key</param>
        /// 
        /// <returns>The size of the key</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public int GetKeySize(IAsymmetricKey Key)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCEncrypt:GetKeySize", "The cipher has not been initialized!", new InvalidOperationException());

            if (Key is MPKCPublicKey)
                return ((MPKCPublicKey)Key).N;
            if (Key is MPKCPrivateKey)
                return ((MPKCPrivateKey)Key).N;

            throw new CryptoAsymmetricException("MPKCEncrypt:GetKeySize", "Unsupported key type!", new ArgumentException());
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="MPKCPublicKey"/> for encryption, or a <see cref="MPKCPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the McEliece public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized or the key is invalid</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is MPKCPublicKey) && !(AsmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "The key is not a valid Ring-KWE key!", new InvalidDataException());

            m_isEncryption = (AsmKey is MPKCPublicKey);

            // init implementation engine
            m_encEngine.Initialize(AsmKey);

            // get the sizes
            if (m_isEncryption)
            {
                if (AsmKey == null)
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "Encryption requires a public key!", new InvalidOperationException());
                if (!(AsmKey is MPKCPublicKey))
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "The public key is invalid!", new ArgumentException());

                m_maxCipherText = ((MPKCPublicKey)AsmKey).N >> 3;
                m_maxPlainText = ((MPKCPublicKey)AsmKey).K >> 3;
            }
            else
            {
                if (AsmKey == null)
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "Decryption requires a private key!", new InvalidOperationException());
                if (!(AsmKey is MPKCPrivateKey))
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "The private key is invalid!", new ArgumentException());

                m_maxPlainText = ((MPKCPrivateKey)AsmKey).K >> 3;
                m_maxCipherText = ((MPKCPrivateKey)AsmKey).N >> 3;
            }

            m_isInitialized = true;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher parameters</param>
        /// 
        /// <returns>An initialized cipher</returns>
        private IMPKCCiphers GetEngine(MPKCParameters CipherParams)
        {
            switch (CipherParams.CCA2Engine)
            {
                case CCA2Ciphers.KobaraImai:
                    return new KobaraImaiCipher(CipherParams);
                case CCA2Ciphers.Pointcheval:
                    return new PointchevalCipher(CipherParams);
                default:
                    return new FujisakiCipher(CipherParams);
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
                    if (m_encEngine != null)
                    {
                        m_encEngine.Dispose();
                        m_encEngine = null;
                    }
                    m_maxPlainText = 0;
                    m_maxCipherText = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}