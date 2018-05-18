#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure
{
    #region DtmForwardKeyStruct
    /// <summary>
    /// The DtmForwardKeyStruct structure.
    /// <para>The DtmForwardKeyStruct structure is used to store the primary session KeyParams, the cipher description, and operation flags.</para>
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
    public struct DtmForwardKeyStruct
    {
        #region Public Fields
        /// <summary>
        /// The forward symmetric cipher key
        /// </summary>
        public KeyParams Key;
        /// <summary>
        /// The forward symmetric cipher description
        /// </summary>
        public DtmSessionStruct SessionParams;
        /// <summary>
        /// The time (in seconds, milliseconds, or ticks) that this key is to be considered valid
        /// </summary>
        public long LifeSpan;
        /// <summary>
        /// A flag indicating a special handling instruction
        /// </summary>
        public short Instruction;
        /// <summary>
        /// Can be additonal information; like a 'valid from' UTC time stamp
        /// </summary>
        public long OptionsFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmForwardKeyStruct primary constructor
        /// </summary>
        /// 
        /// <param name="Key">The forward symmetric cipher key</param>
        /// <param name="SessionParams">The forward symmetric cipher description</param>
        /// <param name="LifeSpan">The time (in seconds, milliseconds, or ticks) that this key is to be considered valid</param>
        /// <param name="Instruction">A flag indicating a special handling instruction</param>
        /// <param name="OptionsFlag">Can be additonal information; like a 'valid from' UTC time stamp</param>
        public DtmForwardKeyStruct(KeyParams Key, DtmSessionStruct SessionParams, long LifeSpan = 0, short Instruction = 0, long OptionsFlag = 0)
        {
            this.Key = Key;
            this.SessionParams = SessionParams;
            this.LifeSpan = LifeSpan;
            this.Instruction = Instruction;
            this.OptionsFlag = OptionsFlag;
        }
        
        /// <summary>
        /// Extracts a DtmForwardKeyStruct from a byte array
        /// </summary>
        /// 
        /// <param name="SessionArray">The byte array containing the DtmForwardKeyStruct structure</param>
        public DtmForwardKeyStruct(byte[] SessionArray) :
            this(new MemoryStream(SessionArray))
        {
        }

        /// <summary>
        /// Constructs a DtmForwardKeyStruct from a stream
        /// </summary>
        /// 
        /// <param name="SessionStream">Stream containing a serialized DtmForwardKeyStruct</param>
        /// 
        /// <returns>A populated DtmForwardKeyStruct</returns>
        public DtmForwardKeyStruct(Stream SessionStream)
        {
            BinaryReader reader = new BinaryReader(SessionStream);

            Key = KeyParams.DeSerialize(SessionStream);
            SessionParams = new DtmSessionStruct(SessionStream);
            LifeSpan = reader.ReadInt64();
            Instruction = reader.ReadInt16();
            OptionsFlag = reader.ReadInt64();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize an DtmForwardKeyStruct
        /// </summary>
        /// 
        /// <param name="ClientStream">Stream containing a serialized DtmForwardKeyStruct</param>
        /// 
        /// <returns>A populated DtmForwardKeyStruct</returns>
        public static DtmForwardKeyStruct DeSerialize(Stream ClientStream)
        {
            return new DtmForwardKeyStruct(ClientStream);
        }

        /// <summary>
        /// Serialize an DtmForwardKeyStruct structure
        /// </summary>
        /// 
        /// <param name="Session">A DtmForwardKeyStruct structure</param>
        /// 
        /// <returns>A stream containing the DtmForwardKeyStruct data</returns>
        public static Stream Serialize(DtmForwardKeyStruct Session)
        {
            return Session.ToStream();
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
            Key.Dispose();
            SessionParams.Reset();
            LifeSpan = 0;
            Instruction = 0;
            OptionsFlag = 0;
        }

        /// <summary>
        /// Returns the DtmForwardKeyStruct as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmSessionStruct</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmForwardKeyStruct as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmForwardKeyStruct</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            KeyParams.Serialize(Key).CopyTo(stream);
            writer.Write(SessionParams.ToBytes());
            writer.Write((long)LifeSpan);
            writer.Write((short)Instruction);
            writer.Write((long)OptionsFlag);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion
    }
    #endregion
}
