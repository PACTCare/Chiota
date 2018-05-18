#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    /// <summary>
    /// A volume file file header structure. 
    /// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/> class.
    /// KeyID and FileId values must each be 16 bytes in length.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.VolumeKey"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct VolumeHeader
    {
        #region Constants
        private const int DSTID_SIZE = 16;
        private const int KEYID_SIZE = 16;
        private const int FILEID_SIZE = 4;
        private const int SIZE_BASEHEADER = 36;
        private const int SEEKTO_KEYID = 16;
        private const int SEEKTO_FILEID = 32;
        #endregion

        #region Public Fields
        /// <summary>
        /// The unique id assigned to an encrypted volume file
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = DSTID_SIZE)]
        public static readonly byte[] DistributionCode = new byte[] { 1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4 };
        /// <summary>
        /// The 16 byte key identifier
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = KEYID_SIZE)]
        public byte[] KeyId;
        /// <summary>
        /// The file identifier
        /// </summary>
        public int FileId;
        #endregion

        #region Constructor
        /// <summary>
        /// VolumeHeader constructor
        /// </summary>
        /// 
        /// <param name="KeyId">A unique 16 byte key ID</param>
        /// <param name="FileId">An encrypted file ID</param>
        public VolumeHeader(byte[] KeyId, int FileId)
        {
            this.KeyId = (byte[])KeyId.Clone();
            this.FileId = FileId;
        }

        /// <summary>
        /// Initialize the VolumeHeader structure using a Stream
        /// </summary>
        /// 
        /// <param name="MessageStream">The Stream containing the VolumeHeader</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the DataStream is too small</exception>
        public VolumeHeader(Stream MessageStream)
        {
            if (MessageStream.Length < SIZE_BASEHEADER)
                throw new CryptoProcessingException("VolumeHeader:CTor", "VolumeHeader stream is too small!", new ArgumentOutOfRangeException());

            MessageStream.Seek(MessageStream.Position + DSTID_SIZE, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(MessageStream);
            
            KeyId = reader.ReadBytes(KEYID_SIZE);
            FileId = reader.ReadInt32();
        }

        /// <summary>
        /// Initialize the VolumeHeader structure using a byte array
        /// </summary>
        /// 
        /// <param name="MessageArray">The byte array containing the VolumeHeader</param>
        public VolumeHeader(byte[] MessageArray)
        {
            MemoryStream ms = new MemoryStream(MessageArray);
            ms.Seek(DSTID_SIZE, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(ms);
            KeyId = reader.ReadBytes(KEYID_SIZE);
            FileId = reader.ReadInt32();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear all struct members
        /// </summary>
        public void Reset()
        {
            if (KeyId != null)
            {
                Array.Clear(KeyId, 0, KeyId.Length);
                KeyId = null;
            }
            FileId = 0;
        }

        /// <summary>
        /// Convert the VolumeHeader structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the VolumeHeader</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the VolumeHeader structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the VolumeHeader</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(DistributionCode);
            writer.Write(KeyId);
            writer.Write(FileId);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Tests if the stream is an encrypted volume file 
        /// </summary>
        /// 
        /// <param name="MessageStream">The file stream</param>
        /// 
        /// <returns>Returns true if stream is a volume file</returns>
        public static bool IsVolumeFile(Stream MessageStream)
        {
            if (MessageStream.Length < SIZE_BASEHEADER)
                return false;

            byte[] dc = new BinaryReader(MessageStream).ReadBytes(DSTID_SIZE);
            MessageStream.Seek(0, SeekOrigin.Begin);

            for (int i = 0; i < dc.Length; ++i)
            {
                if (dc[i] != DistributionCode[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Get the file id
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a volume header</param>
        /// 
        /// <returns>The file id</returns>
        public static int GetFileId(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_FILEID, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadInt32();
        }

        /// <summary>
        /// Get the size of a VolumeHeader
        /// </summary>
        public static int GetHeaderSize { get { return SIZE_BASEHEADER; } }

        /// <summary>
        /// Get the messages unique key identifier
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a volume header</param>
        /// 
        /// <returns>The unique 16 byte id of the key</returns>
        public static byte[] GetKeyId(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_KEYID, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadBytes(KEYID_SIZE);
        }

        /// <summary>
        /// Test for valid header in file
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a volume header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool HasHeader(Stream MessageStream)
        {
            // not a guarantee of valid header
            return MessageStream.Length >= GetHeaderSize;
        }
        #endregion

        #region Setters
        /// <summary>
        /// Set the messages 16 byte File id value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="Id">The volume file id</param>
        public static void SetFileId(Stream MessageStream, int Id)
        {
            MessageStream.Seek(SEEKTO_FILEID, SeekOrigin.Begin);
            BinaryWriter writer = new BinaryWriter(MessageStream);
            writer.Write(Id);
        }

        /// <summary>
        /// Set the messages 16 byte Key id value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="Id">The volume key id</param>
        public static void SetKeyId(Stream MessageStream, byte[] Id)
        {
            MessageStream.Seek(SEEKTO_KEYID, SeekOrigin.Begin);
            MessageStream.Write(Id, 0, KEYID_SIZE);
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
            int hash = ArrayUtils.GetHashCode(KeyId);
            hash += 31 * FileId;

            return hash;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(object Obj)
        {
            if (!(Obj is VolumeHeader))
                return false;

            VolumeHeader other = (VolumeHeader)Obj;

            if (!Compare.IsEqual(KeyId, other.KeyId))
                return false;
            if (FileId != other.FileId)
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
        public static bool operator ==(VolumeHeader X, VolumeHeader Y)
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
        public static bool operator !=(VolumeHeader X, VolumeHeader Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
}
