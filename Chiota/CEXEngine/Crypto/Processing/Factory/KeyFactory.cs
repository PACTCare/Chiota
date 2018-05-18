#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Factory
{
    /// <summary>
    /// KeyFactory: Used to create or extract a CipherKey
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using the <see cref="Create(CipherDescription, SeedGenerators, Digests, int)"/> overload:</description>
    /// <code>
    /// // create the key file
    /// new KeyFactory(KeyStream).Create(CipherDescription);
    /// </code>
    /// 
    /// <description>Example using the <see cref="Extract(out CipherKey, out KeyParams)"/> method:</description>
    /// <code>
    /// KeyParams key;
    /// CipherKey header;
    /// 
    /// new KeyFactory(KeyStream).Extract(out header, out key);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.CipherKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
    /// 
    /// <remarks>
    /// <list type="bullet">
    /// <item><description>Constructor may use a FileStream or a MemoryStream.</description></item>
    /// <item><description>The <see cref="Create(CipherDescription, KeyParams)"/> method requires a populated KeyParams class.</description></item>
    /// <item><description>The <see cref="Create(CipherDescription, SeedGenerators, Digests, int)"/> method auto-generate keying material.</description></item>
    /// <item><description>The Extract() method retrieves a populated cipher key (CipherKey), and key material (KeyParams), from the key stream.</description></item>
    /// </list>
    /// </remarks>
    public sealed class KeyFactory : IDisposable
    {
        #region Fields
        private bool m_isDisposed = false;
        private Stream m_keyStream;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class with a stream; key will be written to or read from the stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The key stream</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a null stream is passed</exception>
        public KeyFactory(Stream KeyStream)
        {
            if (KeyStream == null)
                throw new CryptoProcessingException("KeyFactory:Ctor", "The key stream can not be null!", new ArgumentException());

            m_keyStream = KeyStream;
        }

        private KeyFactory()
        {
        }

        /// <summary>
        /// Finalizer: ensure resources are destroyed
        /// </summary>
        ~KeyFactory()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a single use key file using automatic key material generation.
        /// <para>The Key, and optional IV and IKM are generated automatically using the cipher description contained in the <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>.
        /// This overload creates keying material using the seed and digest engines specified with the <see cref="KeyGenerator"/> class</para>
        /// </summary>
        /// 
        /// <param name="Description">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">Cipher Description</see> containing the cipher implementation details</param>
        /// <param name="SeedEngine">The (optional) <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The (optional) <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// <param name="ExtKeySize">The (optional) size of the extended keying material array.</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a Header parameter does not match a KeyParams value</exception>
        public void Create(CipherDescription Description, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests HashEngine = Digests.SHA512, int ExtKeySize = 0)
        {
            KeyParams keyParam;

            using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, HashEngine, null))
                keyParam = keyGen.GetKeyParams(Description.KeySize, Description.IvSize, Description.MacKeySize, ExtKeySize);

            Create(Description, keyParam);
        }

        /// <summary>
        /// Create a single use key file using a <see cref="KeyParams"/> containing the key material, and a <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/> containing the cipher implementation details
        /// </summary>
        /// 
        /// <param name="Description">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">Cipher Description</see> containing the cipher details</param>
        /// <param name="KeyParam">An initialized and populated key material container; must include a 16 byte populated ExtKey property</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header or a Header parameter does not match a KeyParams value</exception>
        public void Create(CipherDescription Description, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoProcessingException("KeyFactory:Create", "The key can not be null!", new ArgumentNullException());
            
            if (KeyParam.Key.Length != Description.KeySize)
                throw new CryptoProcessingException("KeyFactory:Create", "The key parameter does not match the key size specified in the Header!", new ArgumentOutOfRangeException());

            if (Description.IvSize > 0 && KeyParam.IV != null)
            {
                if (KeyParam.IV.Length != Description.IvSize)
                    throw new CryptoProcessingException("KeyFactory:Create", "The KeyParam IV size does not align with the IVSize setting in the Header!", new ArgumentOutOfRangeException());
            }
            if (Description.MacKeySize > 0)
            {
                if (KeyParam.IKM == null)
                    throw new CryptoProcessingException("KeyFactory:Create", "Digest key is specified in the header MacSize, but is null in KeyParam!", new ArgumentNullException());
                if (KeyParam.IKM.Length != Description.MacKeySize)
                    throw new CryptoProcessingException("KeyFactory:Create", "Header MacSize does not align with the size of the KeyParam IKM!", new ArgumentOutOfRangeException());
            }

            byte[] hdr = new CipherKey(Description).ToBytes();
            m_keyStream.Write(hdr, 0, hdr.Length);
            byte[] key = ((MemoryStream)KeyParams.Serialize(KeyParam)).ToArray();
            m_keyStream.Write(key, 0, key.Length);
        }

        /// <summary>
        /// Create a single use Key file using a manual description of the cipher parameters.
        /// </summary>
        /// 
        /// <param name="KeyParam">An initialized and populated key material container</param>
        /// <param name="EngineType">The Cryptographic <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see></param>
        /// <param name="CipherType">The type of <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">Cipher Mode</see></param>
        /// <param name="PaddingType">The type of cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">Padding Mode</see></param>
        /// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
        /// <param name="Rounds">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        /// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
        /// <param name="MacEngine">The HMAC <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a Header parameter does not match a KeyParams value</exception>
        public void Create(KeyParams KeyParam, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType,
            PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine, int MacSize, Digests MacEngine)
        {
            CipherDescription dsc = new CipherDescription()
            {
                EngineType = (int)EngineType,
                KeySize = KeySize,
                IvSize = (int)IvSize,
                CipherType = (int)CipherType,
                PaddingType = (int)PaddingType,
                BlockSize = (int)BlockSize,
                RoundCount = (int)Rounds,
                KdfEngine = (int)KdfEngine,
                MacEngine = (int)MacEngine,
                MacKeySize = MacSize
            };

            Create(dsc, KeyParam);
        }

        /// <summary>
        /// Extract a KeyParams and CipherKey
        /// </summary>
        /// 
        /// <param name="KeyHeader">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.CipherKey"/> that receives the cipher description, key id, and extension key</param>
        /// <param name="KeyParam">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams"/> container that receives the key material from the file</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the key file could not be found or a Header parameter does not match the keystream length</exception>
        public void Extract(out CipherKey KeyHeader, out KeyParams KeyParam)
        {
            m_keyStream.Seek(0, SeekOrigin.Begin);
            KeyHeader = new CipherKey(m_keyStream);
            CipherDescription dsc = KeyHeader.Description;

            if (m_keyStream.Length < dsc.KeySize + dsc.IvSize + dsc.MacKeySize + CipherKey.GetHeaderSize())
                throw new CryptoProcessingException("KeyFactory:Extract", "The size of the key file does not align with the CipherKey sizes! Key is corrupt.", new ArgumentOutOfRangeException());

            m_keyStream.Seek(CipherKey.GetHeaderSize(), SeekOrigin.Begin);
            KeyParam = KeyParams.DeSerialize(m_keyStream);
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
                m_isDisposed = true;
            }
        }
        #endregion
    }
}
