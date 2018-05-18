#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    #region CipherDescription
    /// <summary>
    /// The CipherDescription structure.
    /// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>, <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CompressionCipher"/>, 
    /// <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.PacketCipher"/>, and <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/> classes.
    /// Contains all the necessary settings required to recreate a cipher instance.</para>
    /// <para>A set of static presets are included to initialize a CipherDescription instance to an AES configuration using CBC or CTR modes.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>CipherDescription</c> structure:</description>
    /// <code>
    ///    CipherDescription dsc = new CipherDescription(
    ///        Engines.RHX,             // cipher engine
    ///        192,                     // key size in bytes
    ///        IVSizes.V128,            // cipher iv size enum
    ///        CipherModes.CTR,         // cipher mode enum
    ///        PaddingModes.X923,       // cipher padding mode enum
    ///        BlockSizes.B128,         // block size enum
    ///        RoundCounts.R18,         // diffusion rounds enum
    ///        Digests.Skein512,        // cipher kdf engine
    ///        64,                      // mac size
    ///        Digests.Keccak);         // mac digest
    /// </code>
    /// 
    /// <description>Using a preset to initialize a <c>CipherDescription</c> structure:</description>
    /// <code>
    /// CipherDescription dsc = CipherDescription.AES256CTR;
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct CipherDescription
    {
        #region Constants
        private const int ENGTPE_SIZE = 1;
        private const int KEYSZE_SIZE = 2;
        private const int IVSIZE_SIZE = 1;
        private const int CPRTPE_SIZE = 1;
        private const int PADTPE_SIZE = 1;
        private const int BLKSZE_SIZE = 1;
        private const int RNDCNT_SIZE = 1;
        private const int KDFENG_SIZE = 1;
        private const int MACSZE_SIZE = 1;
        private const int MACENG_SIZE = 1;
        private const int CPRHDR_SIZE = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE + MACENG_SIZE;

        private const long ENGTPE_SEEK = 0;
        private const long KEYSZE_SEEK = ENGTPE_SIZE;
        private const long IVSIZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE;
        private const long CPRTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
        private const long PADTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE;
        private const long BLKSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE;
        private const long RNDCNT_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE;
        private const long KDFENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;
        private const long MACSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
        private const long MACENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The Cryptographic <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type
        /// </summary>
        public int EngineType;
        /// <summary>
        /// The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeySizes">Key Size</see>
        /// </summary>
        public int KeySize;
        /// <summary>
        /// Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see>
        /// </summary>
        public int IvSize;
        /// <summary>
        /// The type of <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">Cipher Mode</see>
        /// </summary>
        public int CipherType;
        /// <summary>
        /// The type of cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">Padding Mode</see>
        /// </summary>
        public int PaddingType;
        /// <summary>
        /// The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see>
        /// </summary>
        public int BlockSize;
        /// <summary>
        /// The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see>
        /// </summary>
        public int RoundCount;
        /// <summary>
        /// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers
        /// </summary>
        public int KdfEngine;
        /// <summary>
        /// The size of the HMAC key in bytes; a zeroed parameter means authentication is not enabled with this key
        /// </summary>
        public int MacKeySize;
        /// <summary>
        /// The HMAC <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to authenticate a message file encrypted with this key
        /// </summary>
        public int MacEngine;
        #endregion

        #region Constructor
        /// <summary>
        /// CipherDescription constructor
        /// </summary>
        /// 
        /// <param name="EngineType">The Cryptographic <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see></param>
        /// <param name="CipherType">The type of <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">Cipher Mode</see></param>
        /// <param name="PaddingType">The type of cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">Padding Mode</see></param>
        /// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
        /// <param name="RoundCount">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> digest engine used to power the key schedule Key Derivation Function</param>
        /// <param name="MacKeySize">The size of the HMAC key in bytes; a zeroed parameter means authentication is not enabled with this key</param>
        /// <param name="MacEngine">The HMAC <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid KeyId, MessageKey, or ExtensionKey is used</exception>
        public CipherDescription(SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType,
            BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine = Digests.None, int MacKeySize = 0, Digests MacEngine = Digests.None)
        {
            this.EngineType = (int)EngineType;
            this.KeySize = KeySize;
            this.IvSize = (int)IvSize;
            this.CipherType = (int)CipherType;
            this.PaddingType = (int)PaddingType;
            this.BlockSize = (int)BlockSize;
            this.RoundCount = (int)RoundCount;
            this.KdfEngine = (int)KdfEngine;
            this.MacKeySize = MacKeySize;
            this.MacEngine = (int)MacEngine;
        }

        /// <summary>
        /// Initialize the CipherDescription structure using a Stream
        /// </summary>
        /// 
        /// <param name="DescriptionStream">The Stream containing the CipherDescription</param>
        public CipherDescription(Stream DescriptionStream)
        {
            BinaryReader reader = new BinaryReader(DescriptionStream);

            EngineType = reader.ReadByte();
            KeySize = reader.ReadInt16();
            IvSize = reader.ReadByte();
            CipherType = reader.ReadByte();
            PaddingType = reader.ReadByte();
            BlockSize = reader.ReadByte();
            RoundCount = reader.ReadByte();
            KdfEngine = reader.ReadByte();
            MacKeySize = reader.ReadByte();
            MacEngine = reader.ReadByte();
        }

        /// <summary>
        /// Initialize the CipherDescription structure using a byte array
        /// </summary>
        /// 
        /// <param name="DescriptionArray">The byte array containing the CipherDescription</param>
        public CipherDescription(byte[] DescriptionArray) :
            this (new MemoryStream(DescriptionArray))
        {
        }
        #endregion

        #region Presets
        /// <summary>
        /// An AES-128 preset using CBC mode and PKCS7 padding
        /// </summary>
        public static readonly CipherDescription AES128CBC = new CipherDescription (SymmetricEngines.RHX, 16, IVSizes.V128, CipherModes.CBC, PaddingModes.PKCS7, BlockSizes.B128, RoundCounts.R10);

        /// <summary>
        /// An AES-256 preset using CBC mode and PKCS7 padding
        /// </summary>
        public static readonly CipherDescription AES256CBC = new CipherDescription(SymmetricEngines.RHX, 32, IVSizes.V128, CipherModes.CBC, PaddingModes.PKCS7, BlockSizes.B128, RoundCounts.R14);

        /// <summary>
        /// An Rijndael-512 preset using CBC mode and PKCS7 padding
        /// </summary>
        public static readonly CipherDescription AES512CBC = new CipherDescription(SymmetricEngines.RHX, 64, IVSizes.V128, CipherModes.CBC, PaddingModes.PKCS7, BlockSizes.B128, RoundCounts.R22);

        /// <summary>
        /// An AES-128 preset using CTR mode
        /// </summary>
        public static readonly CipherDescription AES128CTR = new CipherDescription(SymmetricEngines.RHX, 16, IVSizes.V128, CipherModes.CTR, PaddingModes.None, BlockSizes.B128, RoundCounts.R10);

        /// <summary>
        /// An AES-256 preset using CTR mode
        /// </summary>
        public static readonly CipherDescription AES256CTR = new CipherDescription(SymmetricEngines.RHX, 32, IVSizes.V128, CipherModes.CTR, PaddingModes.None, BlockSizes.B128, RoundCounts.R14);

        /// <summary>
        /// An Rijndael-512 preset using CTR mode
        /// </summary>
        public static readonly CipherDescription AES512CTR = new CipherDescription(SymmetricEngines.RHX, 64, IVSizes.V128, CipherModes.CTR, PaddingModes.None, BlockSizes.B128, RoundCounts.R22);
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return CPRHDR_SIZE;
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="Description">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(CipherDescription Description)
        {
            // not guaranteed, but should be ok
            return (Description.EngineType < Enum.GetValues(typeof(SymmetricEngines)).Length << 2);
        }

        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            EngineType = 0;
            KeySize = 0;
            IvSize = 0;
            CipherType = 0;
            PaddingType = 0;
            BlockSize = 0;
            RoundCount = 0;
            KdfEngine = 0;
            MacKeySize = 0;
            MacEngine = 0;
        }

        /// <summary>
        /// Convert the CipherDescription structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the CipherDescription</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the CipherDescription structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the CipherDescription</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((byte)EngineType);
            writer.Write((short)KeySize);
            writer.Write((byte)IvSize);
            writer.Write((byte)CipherType);
            writer.Write((byte)PaddingType);
            writer.Write((byte)BlockSize);
            writer.Write((byte)RoundCount);
            writer.Write((byte)KdfEngine);
            writer.Write((byte)MacKeySize);
            writer.Write((byte)MacEngine);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * EngineType;
            hash += 31 * KeySize;
            hash += 31 * IvSize;
            hash += 31 * CipherType;
            hash += 31 * PaddingType;
            hash += 31 * BlockSize;
            hash += 31 * RoundCount;
            hash += 31 * KdfEngine;
            hash += 31 * MacKeySize;
            hash += 31 * MacEngine;

            return hash;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (!(Obj is CipherDescription))
                return false;

            CipherDescription other = (CipherDescription)Obj;

            if (EngineType != other.EngineType)
                return false;
            if (KeySize != other.KeySize)
                return false;
            if (IvSize != other.IvSize)
                return false;
            if (CipherType != other.CipherType)
                return false;
            if (PaddingType != other.PaddingType)
                return false;
            if (BlockSize != other.BlockSize)
                return false;
            if (RoundCount != other.RoundCount)
                return false;
            if (KdfEngine != other.KdfEngine)
                return false;
            if (MacKeySize != other.MacKeySize)
                return false;
            if (MacEngine != other.MacEngine)
                return false;

            return true;
        }

        /// <summary>
        /// Compare this object instance is equal to another
        /// </summary>
        /// 
        /// <param name="X">The first object</param>
        /// <param name="Y">The second object</param>
        /// 
        /// <returns>Equal</returns>
        public static bool operator ==(CipherDescription X, CipherDescription Y)
        {
            return X.Equals(Y);
        }

        /// <summary>
        /// Compare this object instance is not equal to another
        /// </summary>
        /// 
        /// <param name="X">The first object</param>
        /// <param name="Y">The second object</param>
        /// 
        /// <returns>Not equal</returns>
        public static bool operator !=(CipherDescription X, CipherDescription Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
    #endregion
}
