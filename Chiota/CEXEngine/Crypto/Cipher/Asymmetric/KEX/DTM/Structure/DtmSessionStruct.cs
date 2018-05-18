#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure
{
    #region DtmSessionStruct
    /// <summary>
    /// Session Key structure; contains a minimal description of the symmetric cipher.
    /// <para>Used to define a symmetric ciphers parameters, implemented with minimal overhead. 
    /// For use in defining the symmetric cipher parameters over an asymmetric channel.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of creating a <c>DtmSessionStruct</c> structure:</description>
    /// <code>
    ///  // initialize with CipherDescription structure containing all of the settings used by the cipher instance
    ///  DtmSessionStruct session = new DtmSessionStruct(BlockCiphers.RDX, 32, IVSizes.V128);
    /// </code>
    /// <description>Example of writing a KeyParams class to a <c>DtmSessionStruct</c> structure:</description>
    /// <code>
    ///  // write key material to the stream
    ///  DtmSessionStruct.SetKey(keyStream, keyParams);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmClientStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmIdentityStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmSessionStruct
    {
        #region Constants
        private const int ENGTPE_SIZE = 1;
        private const int KEYSZE_SIZE = 2;
        private const int IVSIZE_SIZE = 1;
        private const int RNDCNT_SIZE = 1;
        private const int KDFENG_SIZE = 1;
        private const int HDR_SIZE = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;

        private const long ENGTPE_SEEK = 0;
        private const long KEYSZE_SEEK = ENGTPE_SIZE;
        private const long IVSIZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE;
        private const long RNDCNT_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
        private const long KDFENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + RNDCNT_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The Cryptographic <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type
        /// </summary>
        public byte EngineType;
        /// <summary>
        /// The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeySizes">Key Size</see>
        /// </summary>
        public short KeySize;
        /// <summary>
        /// Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see>
        /// </summary>
        public byte IvSize;
        /// <summary>
        /// The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see>
        /// </summary>
        public byte RoundCount;
        /// <summary>
        /// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers
        /// </summary>
        public byte KdfEngine;
        #endregion

        #region Constructor
        /// <summary>
        /// DtmSessionStruct constructor
        /// </summary>
        /// 
        /// <param name="EngineType">The Cryptographic <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see></param>
        /// <param name="RoundCount">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid KeyId, MessageKey, or ExtensionKey is used</exception>
        public DtmSessionStruct(BlockCiphers EngineType = BlockCiphers.Rijndael, int KeySize = 32, IVSizes IvSize = IVSizes.V128, RoundCounts RoundCount = RoundCounts.R14, Digests KdfEngine = Digests.None)
        {
            this.EngineType = (byte)EngineType;
            this.KeySize = (short)KeySize;
            this.IvSize = (byte)IvSize;
            this.RoundCount = (byte)RoundCount;
            this.KdfEngine = (byte)KdfEngine;
        }
        
        /// <summary>
        /// Initialize the DtmSessionStruct structure using a Stream
        /// </summary>
        /// 
        /// <param name="SessionStream">The Stream containing the DtmSessionStruct</param>
        public DtmSessionStruct(Stream SessionStream)
        {
            BinaryReader reader = new BinaryReader(SessionStream);

            EngineType = reader.ReadByte();
            KeySize = reader.ReadInt16();
            IvSize = reader.ReadByte();
            RoundCount = reader.ReadByte();
            KdfEngine = reader.ReadByte();
        }

        /// <summary>
        /// Initialize the DtmSessionStruct structure using a byte array
        /// </summary>
        /// 
        /// <param name="SessionArray">The byte array containing the DtmSessionStruct</param>
        public DtmSessionStruct(byte[] SessionArray) :
            this (new MemoryStream(SessionArray))
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return HDR_SIZE;
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="Key">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(DtmSessionStruct Key)
        {
            // not guaranteed, but should be ok
            return (Key.EngineType < Enum.GetValues(typeof(SymmetricEngines)).Length);
        }

        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            EngineType = 0;
            KeySize = 0;
            IvSize = 0;
            RoundCount = 0;
            KdfEngine = 0;
        }

        /// <summary>
        /// Convert the DtmSessionStruct structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the DtmSessionStruct</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the DtmSessionStruct structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the DtmSessionStruct</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(EngineType);
            writer.Write(KeySize);
            writer.Write(IvSize);
            writer.Write(RoundCount);
            writer.Write(KdfEngine);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get the key data from the key stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a session key</param>
        /// 
        /// <returns>KeyParams structure</returns>
        public static KeyParams GetKey(Stream KeyStream)
        {
            DtmSessionStruct session = new DtmSessionStruct(KeyStream);
            byte[] key = new byte[session.KeySize];
            byte[] iv = new byte[session.IvSize];

            KeyStream.Seek(HDR_SIZE, SeekOrigin.Begin);
            KeyStream.Read(key, 0, key.Length);
            KeyStream.Read(iv, 0, iv.Length);

            return new KeyParams(key, iv);
        }
        #endregion

        #region Setters
        /// <summary>
        /// Write the key data from the key stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a session key</param>
        /// <param name="KeyParam">KeyParams class containing the keying material</param>
        public static void SetKey(Stream KeyStream, KeyParams KeyParam)
        {
            byte[] key = KeyParam.Key;
            byte[] iv = KeyParam.IV;

            KeyStream.Seek(HDR_SIZE, SeekOrigin.Begin);
            KeyStream.Write(key, 0, key.Length);
            KeyStream.Write(iv, 0, iv.Length);
        }

        /// <summary>
        /// Write the key data from the key stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a session key</param>
        /// <param name="KeyData">A byte array containing the keying material</param>
        public static void SetKey(Stream KeyStream, byte[] KeyData)
        {
            KeyStream.Seek(HDR_SIZE, SeekOrigin.Begin);
            KeyStream.Write(KeyData, 0, KeyData.Length);
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
            if (!(Obj is DtmSessionStruct))
                return false;

            DtmSessionStruct other = (DtmSessionStruct)Obj;

            if (EngineType != other.EngineType)
                return false;
            if (KeySize != other.KeySize)
                return false;
            if (IvSize != other.IvSize)
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
        public static bool operator ==(DtmSessionStruct X, DtmSessionStruct Y)
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
        public static bool operator !=(DtmSessionStruct X, DtmSessionStruct Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
    #endregion
}
