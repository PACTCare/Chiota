#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// An MPKCS One Time Sign (OTS) message sign and verify implementation.
    /// <para>Sign: uses the specified digest to hash a message; the hash value is then encrypted with a McEliece public key.
    /// Verify: decrypts the McEliece cipher text, and then compares the value to a hash of the message.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of using the signing and verifying an array:</description>
    /// <code>
    /// MPKCParameters ps = MPKCParamSets.MPKCFM11T40S256;
    /// MPKCKeyGenerator gen = new MPKCKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// byte[] code;
    /// byte[] data = new byte[100];
    ///
    /// // get the message code for an array of bytes
    /// using (MPKCSign sgn = new MPKCSign(ps))
    /// {
    ///     sgn.Initialize(kp.PublicKey);
    ///     code = sgn.Sign(data, 0, data.Length);
    /// }
    ///
    /// // test the message for validity
    /// using (MPKCSign sgn = new MPKCSign(ps))
    /// {
    ///     sgn.Initialize(kp.PrivateKey);
    ///     bool valid = sgn.Verify(data, 0, data.Length, code);
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
    /// <item><description>Signing is intended as a one time only key implementation (OTS); keys should never be re-used.</description></item>
    /// <item><description>Uses the McEliece CCA2 variants; Fujisaki, KobriImai, or PointCheval ciphers.</description></item>
    /// <item><description>Digests can be any of the implemented digests; Blake, Keccak, SHA-2 or Skein.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCSign : IAsymmetricSign
    {
        #region Constants
        private const string ALG_NAME = "MPKCSign";
        #endregion

        #region Fields
        private IAsymmetricKey m_asmKey;
        private IMPKCCiphers m_asyCipher;
        private IDigest m_dgtEngine;
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
        }

        /// <summary>
        /// Get: This class is initialized for Signing with the Public key
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized</exception>
        public bool IsSigner
        {
            get
            {
                if (!m_isInitialized)
                    throw new CryptoAsymmetricException("MPKCSign:IsSigner", "The signer has not been initialized!", new InvalidOperationException());

                return (m_asmKey is MPKCPublicKey);
            }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized</exception>
        public int MaxPlainText
        {
            get 
            { 
                if (!m_isInitialized)
                    throw new CryptoAsymmetricException("MPKCSign:MaxPlainText", "The signer has not been initialized!", new InvalidOperationException());

                if (m_asmKey is MPKCPublicKey)
                    return ((MPKCPublicKey)m_asmKey).K >> 3; 
                else
                    return ((MPKCPrivateKey)m_asmKey).K >> 3; 
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
        /// <param name="CipherParams">The McEliece cipher used to encrypt the hash</param>
        /// <param name="Digest">The type of digest engine used</param>
        public MPKCSign(MPKCParameters CipherParams, Digests Digest = Digests.SHA512)
        {
            m_dgtEngine = GetDigest(CipherParams.Digest);
            m_asyCipher = GetEngine(CipherParams);
        }

        private MPKCSign()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCSign()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the McEliece Public (Sign) or Private (Verify) key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid keypair is used</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is MPKCPublicKey) && !(AsmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCSign:Initialize", "The key is not a valid RNBW key!", new InvalidDataException());

            Reset();
            m_asmKey = AsmKey;
            m_isInitialized = true;
        }

        /// <summary>
        /// Reset the underlying digest engine
        /// </summary>
        public void Reset()
        {
            m_dgtEngine.Reset();
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized or the key is invalid</exception>
        public byte[] Sign(Stream InputStream)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(m_asmKey is MPKCPublicKey))
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);

            if (m_asyCipher.MaxPlainText < m_dgtEngine.DigestSize)
                throw new CryptoAsymmetricException("MPKCSign:Sign", string.Format("The key size is too small; key supports encrypting up to {0} bytes!", m_asyCipher.MaxPlainText), new ArgumentOutOfRangeException());

            byte[] hash = Compute(InputStream);

            return m_asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="Input">The byte array contining the data</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized, the length is out of range, or the key is invalid</exception>
        public byte[] Sign(byte[] Input, int Offset, int Length)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(m_asmKey is MPKCPublicKey))
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);

            if (m_asyCipher.MaxPlainText < m_dgtEngine.DigestSize)
                throw new CryptoAsymmetricException("MPKCSign:Sign", string.Format("The key size is too small; key supports encrypting up to {0} bytes!", m_asyCipher.MaxPlainText), new ArgumentException());

            byte[] hash = Compute(Input, Offset, Length);

            return m_asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data to test</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized, or the key is invalid</exception>
        public bool Verify(Stream InputStream, byte[] Code)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(m_asmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);
            byte[] chksum = m_asyCipher.Decrypt(Code);
            byte[] hash = Compute(InputStream);

            return Compare.IsEqual(hash, chksum);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="Input">The stream containing the data to test</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized, or the key is invalid</exception>
        public bool Verify(byte[] Input, int Offset, int Length, byte[] Code)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(m_asmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);
            byte[] chksum = m_asyCipher.Decrypt(Code);
            byte[] hash = Compute(Input, Offset, Length);

            return Compare.IsEqual(hash, chksum);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Compute the hash from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(Stream InputStream)
        {
            int length = (int)(InputStream.Length - InputStream.Position);
            int blockSize = m_dgtEngine.BlockSize < length ? length : m_dgtEngine.BlockSize;
            int bytesRead = 0;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                bytesRead = InputStream.Read(buffer, 0, blockSize);
                m_dgtEngine.BlockUpdate(buffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            // last block
            if (bytesTotal < length)
            {
                buffer = new byte[length - bytesTotal];
                bytesRead = InputStream.Read(buffer, 0, buffer.Length);
                m_dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
                bytesTotal += buffer.Length;
            }

            byte[] hash = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Compute the hash from a byte array
        /// </summary>
        /// 
        /// <param name="Input">The data byte array</param>
        /// <param name="Offset">The starting offset within the array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(byte[] Input, int Offset, int Length)
        {
            if (Length < Input.Length - Offset)
                throw new ArgumentOutOfRangeException();

            int blockSize = m_dgtEngine.BlockSize < Length ? Length : m_dgtEngine.BlockSize;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = Length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, blockSize);
                m_dgtEngine.BlockUpdate(buffer, 0, blockSize);
                bytesTotal += blockSize;
            }

            // last block
            if (bytesTotal < Length)
            {
                buffer = new byte[Length - bytesTotal];
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, Math.Min(buffer.Length, Input.Length - bytesTotal));
                m_dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
            }

            byte[] hash = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="DigestType">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the digest is unrecognized or unsupported</exception>
        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoAsymmetricException("MPKCSign:GetDigest", "The digest is unrecognized or unsupported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="CipherParams">The engine type</param>
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
                    if (m_dgtEngine != null)
                    {
                        m_dgtEngine.Dispose();
                        m_dgtEngine = null;
                    }
                    if (m_asyCipher != null)
                    {
                        m_asyCipher.Dispose();
                        m_asyCipher = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
