#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure
{
    #region DtmIdentityStruct
    /// <summary>
    /// The DtmIdentityStruct structure; contains the identity field and session information for a host.
    /// <para>This structure is used as storage for the active identity, symmetric session, and asymmetric parameters.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmClientStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmSessionStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmIdentityStruct
    {
        #region Public Fields
        /// <summary>
        /// The active Identity field; used to identify a host in the key exchange
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray)]
        public byte[] Identity;
        /// <summary>
        /// The Asymmetric parameters Id; can be the Asymmetric cipher parameters OId, or a serialized Asymmetric Parameters class
        /// </summary>
        public byte[] PkeId;
        /// <summary>
        /// The Symmetric sessions cipher parameters; contains a complete description of the Symmetric cipher
        /// </summary>
        public DtmSessionStruct Session;
        /// <summary>
        /// This flag can be used as a time stamp indicating the expiry time of the corresponding session key
        /// </summary>
        public long OptionFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// DtmIdentityStruct partial constructor; used for the <c>Init</c> exchange and contains an empty Secret Id
        /// </summary>
        /// 
        /// <param name="Identity">The active Identity field; used to first identify a host during the <c>Init</c> stage of a key exchange</param>
        /// <param name="PkeId">The Asymmetric parameters Id; can be the Asymmetric cipher parameters OId, or a serialized Asymmetric Parameters class</param>
        /// <param name="Session">The Symmetric sessions cipher parameters; contains a complete description of the Symmetric cipher</param>
        /// <param name="OptionFlag">This flag can be used as a time stamp indicating the expiry time of the corresponding session key</param>
        public DtmIdentityStruct(byte[] Identity, byte[] PkeId, DtmSessionStruct Session, long OptionFlag)
        {
            this.Identity = new byte[Identity.Length];
            Array.Copy(Identity, this.Identity, Identity.Length);
            this.PkeId = new byte[PkeId.Length];
            Array.Copy(PkeId, this.PkeId, PkeId.Length);
            this.Session = Session;
            this.OptionFlag = OptionFlag;
        }

        /// <summary>
        /// Extracts a DtmIdentityStruct from a byte array
        /// </summary>
        /// 
        /// <param name="IdentityArray">The byte array containing the DtmIdentityStruct structure</param>
        public DtmIdentityStruct(byte[] IdentityArray) :
            this(new MemoryStream(IdentityArray))
        {
        }

        /// <summary>
        /// Extracts a DtmIdentityStruct from a Stream
        /// </summary>
        /// 
        /// <param name="IdentityStream">The Stream containing the DtmIdentityStruct structure</param>
        public DtmIdentityStruct(Stream IdentityStream)
        {
            BinaryReader reader = new BinaryReader(IdentityStream);
            int len;
            byte[] data;

            len = reader.ReadInt32();
            Identity = reader.ReadBytes(len);
            len = reader.ReadInt32();
            PkeId = reader.ReadBytes(len);
            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            Session = new DtmSessionStruct(data);
            OptionFlag = reader.ReadInt64();
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Deserialize a <see cref="DtmIdentityStruct"/>
        /// </summary>
        /// 
        /// <param name="IdentityStream">Stream containing a serialized DtmIdentityStruct</param>
        /// 
        /// <returns>A populated DtmIdentityStruct</returns>
        public static DtmIdentityStruct DeSerialize(Stream IdentityStream)
        {
            return new DtmIdentityStruct(IdentityStream);
        }

        /// <summary>
        /// Serialize a <see cref="DtmIdentityStruct"/> structure
        /// </summary>
        /// 
        /// <param name="Identity">A DtmIdentityStruct structure</param>
        /// 
        /// <returns>A stream containing the DtmIdentityStruct data</returns>
        public static Stream Serialize(DtmIdentityStruct Identity)
        {
            return Identity.ToStream();
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
            Array.Clear(Identity, 0, Identity.Length);
            Array.Clear(PkeId, 0, PkeId.Length);
            Session.Reset();
            OptionFlag = 0;
        }

        /// <summary>
        /// Returns the DtmParameters as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmIdentityStruct</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmPacket as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmPacket</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);
            byte[] data;

            writer.Write((int)Identity.Length);
            writer.Write(Identity);
            writer.Write((int)PkeId.Length);
            writer.Write(PkeId);
            data = Session.ToBytes();
            writer.Write((int)data.Length);
            writer.Write(data);
            writer.Write((long)OptionFlag);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion
    }
    #endregion
}
