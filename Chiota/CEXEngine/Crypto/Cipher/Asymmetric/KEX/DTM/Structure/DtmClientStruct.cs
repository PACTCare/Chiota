#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure
{
    #region DtmClientStruct
    /// <summary>
    /// The DtmClientStruct structure.
    /// <para>The DtmClientStruct structure is used to store data that uniquely identifies the host.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmIdentityStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmSessionStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex"/>
    /// 
    /// <remarks>
    /// <para>The PublicId field is a byte array used as a unique id, presented to other operators as a host identifier 
    /// during the <c>Auth-Stage</c> of the key exchange.
    /// The SecretId is a byte array that can be a serialized object like a key, or code, and is used to identify 
    /// the host during the <c>Primary-Stage</c> of the key exchange.</para>
    /// </remarks>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmClientStruct
    {
        #region Public Fields
        /// <summary>
        /// The <c>Auth-Stage</c> Public Identity field
        /// </summary>
        public byte[] PublicId;
        /// <summary>
        /// The <c>Primary-Stage</c> Secret Identity field
        /// </summary>
        public byte[] SecretId;
        /// <summary>
        /// The options flag; can be used as additional information about the client structure
        /// </summary>
        public long OptionsFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmClientStruct primary constructor
        /// </summary>
        /// 
        /// <param name="PublicId">The <c>Auth-Stage</c> Public Identity</param>
        /// <param name="SecretId">The <c>Primary-Stage</c> Secret Identity</param>
        /// <param name="OptionsFlag">A flag used for additional information</param>
        public DtmClientStruct(byte[] PublicId, byte[] SecretId, long OptionsFlag = 0)
        {
            this.PublicId = new byte[PublicId.Length];
            Array.Copy(PublicId, this.PublicId, PublicId.Length);
            this.SecretId = new byte[SecretId.Length];
            Array.Copy(SecretId, this.SecretId, SecretId.Length);
            this.OptionsFlag = OptionsFlag;
        }
        
        /// <summary>
        /// Extracts a DtmClientStruct from a byte array
        /// </summary>
        /// 
        /// <param name="ClientArray">The byte array containing the DtmClientStruct structure</param>
        public DtmClientStruct(byte[] ClientArray) :
            this(new MemoryStream(ClientArray))
        {
        }

        /// <summary>
        /// Constructs a DtmClientStruct from a stream
        /// </summary>
        /// 
        /// <param name="ClientStream">Stream containing a serialized DtmClientStruct</param>
        /// 
        /// <returns>A populated DtmClientStruct</returns>
        public DtmClientStruct(Stream ClientStream)
        {
            BinaryReader reader = new BinaryReader(ClientStream);
            int len = reader.ReadInt32();
            PublicId = reader.ReadBytes(len);
            len = reader.ReadInt32();
            SecretId = reader.ReadBytes(len);
            OptionsFlag = reader.ReadInt64();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize an DtmClientStruct
        /// </summary>
        /// 
        /// <param name="ClientStream">Stream containing a serialized DtmClientStruct</param>
        /// 
        /// <returns>A populated DtmClientStruct</returns>
        public static DtmClientStruct DeSerialize(Stream ClientStream)
        {
            return new DtmClientStruct(ClientStream);
        }

        /// <summary>
        /// Serialize an DtmClientStruct structure
        /// </summary>
        /// 
        /// <param name="Client">A DtmClientStruct structure</param>
        /// 
        /// <returns>A stream containing the DtmClientStruct data</returns>
        public static Stream Serialize(DtmClientStruct Client)
        {
            return Client.ToStream();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public int GetHeaderSize()
        {
            return (int)Serialize(this).Length;
        }
        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            OptionsFlag = 0;
            Array.Clear(PublicId, 0, PublicId.Length);
            Array.Clear(SecretId, 0, SecretId.Length);
        }

        /// <summary>
        /// Returns the DtmClientStruct as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmClientStruct</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmClientStruct as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmClientStruct</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((int)PublicId.Length);
            writer.Write(PublicId);
            writer.Write((int)SecretId.Length);
            writer.Write(SecretId);
            writer.Write((long)OptionsFlag);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion
    }
    #endregion
}
