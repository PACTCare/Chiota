#region Directives
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Factory
{
    /// <summary>
    /// VolumeFactory: Used to create and extract a VolumeKey file.
    /// 
    /// <list type="bullet">
    /// <item><description>Constructors may use a fully qualified path to a key file, or the keys file stream.</description></item>
    /// <item><description>The <see cref="Create(VolumeKey, SeedGenerators, Digests)"/> method auto-generate keying material.</description></item>
    /// </list>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using the <see cref="Create(CipherDescription, int)"/> overload:</description>
    /// <code>
    ///     string[] paths = DirectoryTools.GetFiles(InputDirectory);
    /// 
    ///     // set cipher paramaters
    ///     CipherDescription desc = new CipherDescription(
    ///         Engines.RHX, 32,
    ///         IVSizes.V128,
    ///         CipherModes.CTR,
    ///         PaddingModes.X923,
    ///         BlockSizes.B128,
    ///         RoundCounts.R14,
    ///         Digests.Keccak512,
    ///         64,
    ///         Digests.Keccak512);
    /// 
    ///     // define the volume key
    ///     VolumeKey vkey = new VolumeKey(desc, paths.Length);
    ///     
    ///     // key will be written to this stream
    ///     MemoryStream keyStream = new MemoryStream();
    /// 
    ///     // create the volume key stream
    ///     using (VolumeFactory vf = new VolumeFactory())
    ///         keyStream = vf.Create(vkey);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.VolumeKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/>
    public sealed class VolumeFactory
    {
        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public VolumeFactory()
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a volume key file using automatic key material generation.
        /// <para>The Key, and IV sets are generated automatically using the cipher description contained in the <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>.
        /// This overload creates keying material using the seed and digest engines specified with the <see cref="KeyGenerator"/> class</para>
        /// </summary>
        /// 
        /// <param name="Key">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.VolumeKey">VolumeKey</see> containing the cipher and key implementation details</param>
        /// <param name="SeedEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// 
        /// <returns>A populated VolumeKey</returns>
        public MemoryStream Create(VolumeKey Key, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests HashEngine = Digests.SHA512)
        {
            int ksize = Key.Count * (Key.Description.KeySize + Key.Description.IvSize);
            byte[] kdata;

            using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, HashEngine, null))
                kdata = keyGen.GetBytes(ksize);

            MemoryStream keyStream = new MemoryStream();
            byte[] hdr = Key.ToBytes();
            keyStream.Write(hdr, 0, hdr.Length);
            keyStream.Write(kdata, 0, kdata.Length);
            keyStream.Seek(0, SeekOrigin.Begin);

            return keyStream;
        }

        /// <summary>
        /// Create a volume key file using a <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/> containing the cipher implementation details, and a key count size
        /// </summary>
        /// 
        /// <param name="Description">The >Cipher Description containing the cipher details</param>
        /// <param name="KeyCount">The number of key sets associated with this volume key</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        /// 
        /// <returns>A populated VolumeKey</returns>
        public MemoryStream Create(CipherDescription Description, int KeyCount)
        {
            return this.Create(new VolumeKey(Description, KeyCount));
        }

        /// <summary>
        /// Create a volume key file using a manual description of the cipher parameters.
        /// </summary>
        /// 
        /// <param name="KeyCount">The number of key sets associated with this volume key</param>
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
        /// <returns>A populated VolumeKey</returns>
        public MemoryStream Create(int KeyCount, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType,
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

            return Create(dsc, KeyCount);
        }

        /// <summary>
        /// Extract a KeyParams and CipherDescription from a VolumeKey stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Index">The index of the key set to extract</param>
        /// <param name="Description">The <see cref="CipherDescription"/> that receives the cipher description</param>
        /// <param name="KeyParam">The <see cref="KeyParams"/> container that receives the key material from the file</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the key file could not be found</exception>
        public void Extract(Stream KeyStream, int Index, out CipherDescription Description, out KeyParams KeyParam)
        {
            if (KeyStream == null || KeyStream.Length < 96)
                throw new CryptoProcessingException("VolumeFactory:Extract", "The key file could not be loaded! Check the stream.", new FileNotFoundException());

            VolumeKey vkey = new VolumeKey(KeyStream);
            Description = vkey.Description;
            KeyParam = VolumeKey.AtIndex(KeyStream, Index);
        }
        #endregion
    }
}
