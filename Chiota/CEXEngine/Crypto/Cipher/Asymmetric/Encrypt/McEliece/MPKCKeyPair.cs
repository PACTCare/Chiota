#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.CryptoException;
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// An McEliece Key-Pair container
    /// </summary>
    public sealed class MPKCKeyPair : IAsymmetricKeyPair
    {
        #region Constants
        private const string ALG_NAME = "MPKCKeyPair";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private IAsymmetricKey m_publicKey;
        private IAsymmetricKey m_privateKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: KeyPair name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Returns the public key parameters
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return m_publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key parameters
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return m_privateKey; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="PublicKey">The public key</param>
        /// <param name="PrivateKey">The corresponding private key</param>
        public MPKCKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            m_publicKey = PublicKey;
            m_privateKey = PrivateKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public MPKCKeyPair(IAsymmetricKey Key)
        {
            if (Key is MPKCPublicKey)
                m_publicKey = (MPKCPublicKey)Key;
            else if (Key is MPKCPrivateKey)
                m_privateKey = (MPKCPrivateKey)Key;
            else
                throw new CryptoAsymmetricException("MPKCKeyPair:Ctor", "Not a valid McEliece key!", new ArgumentException());
        }
        
        /// <summary>
        /// Reads a key pair from an input stream.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key pair</param>
        public MPKCKeyPair(MemoryStream KeyStream)
        {
            m_publicKey = new MPKCPublicKey(KeyStream);
            m_privateKey = new MPKCPrivateKey(KeyStream);
        }

        /// <summary>
        /// Reads a key pair  from a byte array.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">An byte array containing an encoded key pair</param>
        public MPKCKeyPair(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private MPKCKeyPair()
        {
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this key pair instance
        /// </summary>
        /// 
        /// <returns>The IAsymmetricKeyPair copy</returns>
        public object Clone()
        {
            return new MPKCKeyPair((IAsymmetricKey)m_publicKey.Clone(), (IAsymmetricKey)m_privateKey.Clone());
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
                    if (m_privateKey != null)
                        ((MPKCPrivateKey)m_privateKey).Dispose();
                    if (m_publicKey != null)
                        ((MPKCPublicKey)m_publicKey).Dispose();
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
