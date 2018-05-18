#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure
{
    #region DtmFileInfoSruct
    /// <summary>
    /// The DtmFileInfoSruct structure.
    /// <para>The DtmFileInfoSruct structure is a header that preceedes a file.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmClientStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmIdentityStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmSessionStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmFileInfoSruct
    {
        #region Public Fields
        /// <summary>
        /// The file name
        /// </summary>
        public string FileName;
        /// <summary>
        /// The total number of file bytes in the file
        /// </summary>
        public long FileSize;
        /// <summary>
        /// Flag used to identify the type of payload and options
        /// </summary>
        public long OptionsFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmFileInfoSruct primary constructor
        /// </summary>
        /// 
        /// <param name="FileName">The file name</param>
        /// <param name="FileSize">The total number of file bytes in the file</param>
        /// <param name="OptionsFlag">The total length of the stream</param>
        public DtmFileInfoSruct(string FileName = "", long FileSize = 0, long OptionsFlag = 0)
        {
            this.FileName = FileName;
            this.FileSize = FileSize;
            this.OptionsFlag = OptionsFlag;
        }

        /// <summary>
        /// Constructs a DtmFileInfoSruct from a byte array
        /// </summary>
        /// 
        /// <param name="FragmentArray">The byte array containing the DtmFileInfoSruct structure</param>
        public DtmFileInfoSruct(byte[] FragmentArray) :
            this(new MemoryStream(FragmentArray))
        {
        }

        /// <summary>
        /// Constructs a DtmIdentityStruct from a stream
        /// </summary>
        /// 
        /// <param name="InfoStream">Stream containing a serialized DtmFileInfoSruct</param>
        /// 
        /// <returns>A populated DtmFileInfoSruct</returns>
        public DtmFileInfoSruct(Stream InfoStream)
        {
            BinaryReader reader = new BinaryReader(InfoStream);
            int len = reader.ReadInt32();
            if (len > 0)
            {
                byte[] name = reader.ReadBytes(len);
                FileName = System.Text.Encoding.Unicode.GetString(name);
            }
            else
            {
                FileName = "";
            }
            FileSize = reader.ReadInt64();
            OptionsFlag = reader.ReadInt64();
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Deserialize an DtmFileInfoSruct
        /// </summary>
        /// 
        /// <param name="InfoStream">Stream containing a serialized DtmFileInfoSruct</param>
        /// 
        /// <returns>A populated DtmFileInfoSruct</returns>
        public static DtmFileInfoSruct DeSerialize(Stream InfoStream)
        {
            return new DtmFileInfoSruct(InfoStream);
        }

        /// <summary>
        /// Serialize an DtmFileInfoSruct structure
        /// </summary>
        /// 
        /// <param name="FileInfo">A DtmFileInfoSruct structure</param>
        /// 
        /// <returns>A stream containing the DtmFileInfoSruct data</returns>
        public static Stream Serialize(DtmFileInfoSruct FileInfo)
        {
            return FileInfo.ToStream();
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
            FileName = "";
            FileSize = 0;
            OptionsFlag = 0;
        }
        /// <summary>
        /// Returns the DtmFileInfoSruct as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmFileInfoSruct</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmFileInfoSruct as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmFileInfoSruct</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            byte[] name = System.Text.Encoding.Unicode.GetBytes(FileName);
            writer.Write((int)name.Length);
            writer.Write(name);
            writer.Write((long)FileSize);
            writer.Write((long)OptionsFlag);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion
    }
    #endregion
}
