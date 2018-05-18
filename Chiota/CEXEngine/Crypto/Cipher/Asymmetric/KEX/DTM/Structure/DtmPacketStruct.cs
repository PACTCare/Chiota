#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure
{
    #region DtmPacket
    /// <summary>
    /// The DtmPacketStruct structure.
    /// The primary packet header used in a DTM key exchange; used to classify and describe the message content.
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmClientStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmIdentityStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmSessionStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmPacketStruct
    {
        #region Constants
        private const int MSGTPE_SIZE = 2;
        private const int PAYLEN_SIZE = 8;
        private const int SEQNUM_SIZE = 4;
        private const int PKTFLG_SIZE = 2;
        private const int OPTFLG_SIZE = 8;
        private const int HDR_SIZE = MSGTPE_SIZE + PAYLEN_SIZE + SEQNUM_SIZE + PKTFLG_SIZE + OPTFLG_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The <see cref="DtmPacketFlags"/> message type; describes the packet classification
        /// </summary>
        public DtmPacketFlags PacketType;
        /// <summary>
        /// The length in bytes of the payload contained in the packet
        /// </summary>
        public long PayloadLength;
        /// <summary>
        /// The packet sequence number
        /// </summary>
        public int Sequence;
        /// <summary>
        /// The packet type flag, signifies the operation type
        /// </summary>
        public short PacketFlag;
        /// <summary>
        /// The packet header option flag
        /// </summary>
        public long OptionFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// DtmPacketStruct primary constructor
        /// </summary>
        /// 
        /// <param name="PacketType">The <see cref="DtmPacketFlags"/> message type; describes the packet classification</param>
        /// <param name="PayloadLength">The length of the payload contained in the packet</param>
        /// <param name="Sequence">The packet sequence number</param>
        /// <param name="PacketFlag">The <see cref="DtmServiceFlags"/> exchange state; indicates the exchange state position</param>
        /// <param name="OptionFlag">The packet header option flag</param>
        public DtmPacketStruct(DtmPacketFlags PacketType, long PayloadLength, int Sequence, short PacketFlag, long OptionFlag = 0)
        {
            this.PacketType = PacketType;
            this.PayloadLength = PayloadLength;
            this.Sequence = Sequence;
            this.PacketFlag = PacketFlag;
            this.OptionFlag = OptionFlag;
        }

        /// <summary>
        /// Extracts a DtmPacket from a byte array
        /// </summary>
        /// 
        /// <param name="PacketArray">The byte array containing the DtmPacket structure</param>
        public DtmPacketStruct(byte[] PacketArray) :
            this(new MemoryStream(PacketArray))
        {
        }

        /// <summary>
        /// Extracts a DtmPacket from a Stream
        /// </summary>
        /// 
        /// <param name="PacketStream">The Stream containing the DtmPacket structure</param>
        public DtmPacketStruct(Stream PacketStream)
        {
            BinaryReader reader = new BinaryReader(PacketStream);
            PacketType = (DtmPacketFlags)reader.ReadUInt16();
            PayloadLength = reader.ReadInt64();
            Sequence = reader.ReadInt32();
            PacketFlag = reader.ReadInt16();
            OptionFlag = reader.ReadInt64();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Returns the DtmPacket as a byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmPacket</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmPacket as a MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmPacket</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((short)PacketType);
            writer.Write((long)PayloadLength);
            writer.Write((int)Sequence);
            writer.Write((short)PacketFlag);
            writer.Write((long)OptionFlag);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }

        /// <summary>
        /// Deserialize a <see cref="DtmPacketStruct"/>
        /// </summary>
        /// 
        /// <param name="PacketStream">Stream containing a serialized DtmPacketStruct</param>
        /// 
        /// <returns>A populated DtmPacketStruct</returns>
        public static DtmPacketStruct DeSerialize(Stream PacketStream)
        {
            return new DtmPacketStruct(PacketStream);
        }

        /// <summary>
        /// Serialize a <see cref="DtmPacketStruct"/> structure
        /// </summary>
        /// 
        /// <param name="Packet">A DtmPacketStruct structure</param>
        /// 
        /// <returns>A stream containing the DtmPacketStruct data</returns>
        public static Stream Serialize(DtmPacketStruct Packet)
        {
            return Packet.ToStream();
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
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            PacketType = 0;
            PayloadLength = 0;
            Sequence = 0;
            PacketFlag = 0;
            OptionFlag = 0;
        }
        #endregion
    }
    #endregion
}
