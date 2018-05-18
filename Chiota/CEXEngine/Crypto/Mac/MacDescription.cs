#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    #region MacDescription
    /// <summary>
    /// The MacDescription structure.
    /// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.MacStream"/> class.
    /// Contains all the necessary settings required to recreate a Mac instance.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>MacDescription</c> for an Hmac:</description>
    /// <code>
    ///    MacDescription msc = new MacDescription(
    ///        Digests.SHA512,          // hmac engine
    ///        128);                    // key size in bytes
    /// </code>
    /// 
    /// <description>Using a preset to initialize a <c>MacDescription</c> structure:</description>
    /// <code>
    /// MacDescription dsc = MacDescription.AES256CTR;
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
    public struct MacDescription
    {
        #region Constants
        private const int MACTPE_SIZE = 1;
        private const int KEYSZE_SIZE = 2;
        private const int IVSIZE_SIZE = 1;
        private const int MACENG_SIZE = 1;
        private const int ENGTPE_SIZE = 1;
        private const int BLKSZE_SIZE = 1;
        private const int RNDCNT_SIZE = 1;
        private const int KDFENG_SIZE = 1;
        private const int MACHDR_SIZE = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + ENGTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
        private const long MACTPE_SEEK = 0;
        private const long KEYSZE_SEEK = MACTPE_SIZE;
        private const long IVSIZE_SEEK = MACTPE_SIZE + KEYSZE_SIZE;
        private const long MACENG_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
        private const long MACKEY_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE;
        private const long ENGTPE_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE;
        private const long BLKSZE_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + ENGTPE_SIZE;
        private const long RNDCNT_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE+ ENGTPE_SIZE + BLKSZE_SIZE;
        private const long KDFENG_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + ENGTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The type of Mac engine to use; CMac, Hmac, or Vmac.
        /// </summary>
        public int MacType;
        /// <summary>
        /// The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeySizes">Key Size</see>
        /// </summary>
        public int KeySize;
        /// <summary>
        /// Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see>
        /// </summary>
        public int IvSize;
        /// <summary>
        /// The HMAC <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to authenticate a message file encrypted with this key
        /// </summary>
        public int HmacEngine;
        /// <summary>
        /// The symmetric block cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">Engine</see> type
        /// </summary>
        public int EngineType;
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
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the structure with parameters for any supported type of Mac generator
        /// </summary>
        /// 
        /// <param name="MacType">The type of Mac generator; Cmac, Hmac, or Vmac</param>
        /// <param name="KeySize">The mac/cipher key size in bytes</param>
        /// <param name="IvSize">Size of the Mac Initialization Vector</param>
        /// <param name="HmacEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used in the Hmac</param>
        /// <param name="EngineType">The symmetric block cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
        /// <param name="RoundCount">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
        /// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
        /// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        public MacDescription(Macs MacType, int KeySize, int IvSize, Digests HmacEngine = Digests.SHA512, BlockCiphers EngineType = BlockCiphers.Rijndael, 
            RoundCounts RoundCount = RoundCounts.R14, BlockSizes BlockSize = BlockSizes.B128, Digests KdfEngine = Digests.SHA512)
        {
            this.MacType = (int)MacType;
            this.KeySize = KeySize;
            this.IvSize = IvSize;
            this.HmacEngine = (int)HmacEngine;
            this.EngineType = (int)EngineType;
            this.RoundCount = (int)RoundCount;
            this.BlockSize = (int)BlockSize;
            this.KdfEngine = (int)KdfEngine;
        }

        /// <summary>
        /// Initialize the structure with parameters for an HMAC generator
        /// </summary>
        /// 
        /// <param name="KeySize">The Mac key size in bytes</param>
        /// <param name="HmacEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used in the Hmac</param>
        public MacDescription(int KeySize, Digests HmacEngine)
        {
            MacType = (int)Macs.HMAC;
            this.KeySize = KeySize;
            this.HmacEngine = (int)HmacEngine;
            IvSize = 0;
            EngineType = 0;
            BlockSize = 0;
            RoundCount = 0;
            KdfEngine = 0;
        }

        /// <summary>
        /// Initialize the structure with parameters for an CMAC generator
        /// </summary>
        /// 
        /// <param name="KeySize">The Mac key size in bytes</param>
        /// <param name="EngineType">The symmetric block cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
        /// <param name="IvSize">Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see></param>
        /// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
        /// <param name="RoundCount">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        public MacDescription(int KeySize, BlockCiphers EngineType, IVSizes IvSize, BlockSizes BlockSize = BlockSizes.B128, RoundCounts RoundCount = RoundCounts.R14, Digests KdfEngine = Digests.SHA512)
        {
            MacType = (int)Macs.CMAC;
            this.KeySize = KeySize;
            this.IvSize = (int)IvSize;
            HmacEngine = 0;
            this.EngineType = (int)EngineType;
            this.BlockSize = (int)BlockSize;
            this.RoundCount = (int)RoundCount;
            this.KdfEngine = (int)KdfEngine;
        }

        /// <summary>
        /// Initialize the MacDescription structure using a Stream
        /// </summary>
        /// 
        /// <param name="DescriptionStream">The Stream containing the MacDescription</param>
        public MacDescription(Stream DescriptionStream)
        {
            BinaryReader reader = new BinaryReader(DescriptionStream);
            MacType = reader.ReadByte();
            KeySize = reader.ReadInt16();
            IvSize = reader.ReadByte();
            HmacEngine = reader.ReadByte();
            EngineType = reader.ReadByte();
            BlockSize = reader.ReadByte();
            RoundCount = reader.ReadByte();
            KdfEngine = reader.ReadByte();
        }

        /// <summary>
        /// Initialize the MacDescription structure using a byte array
        /// </summary>
        /// 
        /// <param name="DescriptionArray">The byte array containing the MacDescription</param>
        public MacDescription(byte[] DescriptionArray) :
            this(new MemoryStream(DescriptionArray))
        {
        }
        #endregion

        #region Presets

        #endregion

        #region Public Methods
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return MACHDR_SIZE;
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="Description">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(MacDescription Description)
        {
            // not guaranteed, but should be ok
            return (Description.KeySize != 0 && Description.EngineType != 0 && Description.HmacEngine != 0);
        }

        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            MacType = 0;
            KeySize = 0;
            IvSize = 0;
            HmacEngine = 0;
            EngineType = 0;
            BlockSize = 0;
            RoundCount = 0;
            KdfEngine = 0;
        }

        /// <summary>
        /// Convert the MacDescription structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the MacDescription</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the MacDescription structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the MacDescription</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((byte)MacType);
            writer.Write((short)KeySize);
            writer.Write((byte)IvSize);
            writer.Write((byte)HmacEngine);
            writer.Write((byte)EngineType);
            writer.Write((byte)BlockSize);
            writer.Write((byte)RoundCount);
            writer.Write((byte)KdfEngine);

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
            int hash = 31 * MacType;
            hash += 31 * KeySize;
            hash += 31 * IvSize;
            hash += 31 * HmacEngine;
            hash += 31 * EngineType;
            hash += 31 * BlockSize;
            hash += 31 * RoundCount;
            hash += 31 * KdfEngine;

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
            if (!(Obj is MacDescription))
                return false;

            MacDescription other = (MacDescription)Obj;

            if (MacType != other.MacType)
                return false;
            if (KeySize != other.KeySize)
                return false;
            if (IvSize != other.IvSize)
                return false;
            if (HmacEngine != other.HmacEngine)
                return false;
            if (EngineType != other.EngineType)
                return false;
            if (BlockSize != other.BlockSize)
                return false;
            if (RoundCount != other.RoundCount)
                return false;
            if (KdfEngine != other.KdfEngine)
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
        public static bool operator ==(MacDescription X, MacDescription Y)
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
        public static bool operator !=(MacDescription X, MacDescription Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
    #endregion
}
