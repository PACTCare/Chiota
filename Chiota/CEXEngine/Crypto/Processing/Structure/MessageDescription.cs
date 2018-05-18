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
    /// An encrypted message file header structure. 
    /// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/> class.
    /// KeyID and Extension values must each be 16 bytes in length.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct MessageDescription
    {
        #region Constants
        private const int MACLEN_SIZE = 2;
        private const int KEYUID_SIZE = 16;
        private const int EXTKEY_SIZE = 16;
        private const int SEEKTO_MACLEN = 0;
        private const int SEEKTO_KEYUID = MACLEN_SIZE;
        private const int SEEKTO_EXTKEY = MACLEN_SIZE + KEYUID_SIZE;
        private const int SIZE_HDRBSE = MACLEN_SIZE + KEYUID_SIZE + EXTKEY_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The HMAC hash length
        /// </summary>
        public short MacCodeLength;
        /// <summary>
        /// The 16 byte key identifier
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] KeyID;
        /// <summary>
        /// The encrypted message file extension
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Extension;
        #endregion

        #region Constructor
        /// <summary>
        /// MessageDescription constructor
        /// </summary>
        /// 
        /// <param name="KeyId">A unique 16 byte key ID</param>
        /// <param name="Extension">A 16 byte encrypted file extension</param>
        /// <param name="MacCodeLength">The message hash value length; the default is 0</param>
        public MessageDescription(byte[] KeyId, byte[] Extension, int MacCodeLength = 0)
        {
            this.MacCodeLength = (short)MacCodeLength;
            this.KeyID = KeyId;
            this.Extension = new byte[16];
            Extension.CopyTo(this.Extension, 0);
        }

        /// <summary>
        /// Initialize the MessageDescription structure using a Stream
        /// </summary>
        /// 
        /// <param name="HeaderStream">The Stream containing the MessageDescription</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the DataStream is too small</exception>
        public MessageDescription(Stream HeaderStream)
        {
            BinaryReader reader = new BinaryReader(HeaderStream);
            MacCodeLength = reader.ReadInt16();
            KeyID = reader.ReadBytes(KEYUID_SIZE);
            Extension = reader.ReadBytes(EXTKEY_SIZE);
        }

        /// <summary>
        /// Initialize the MessageDescription structure using a byte array
        /// </summary>
        /// 
        /// <param name="HeaderArray">The byte array containing the MessageDescription</param>
        public MessageDescription(byte[] HeaderArray)
        {
            MemoryStream ms = new MemoryStream(HeaderArray);
            BinaryReader reader =  new BinaryReader(ms);
            MacCodeLength = reader.ReadInt16();
            KeyID = reader.ReadBytes(KEYUID_SIZE);
            Extension = reader.ReadBytes(EXTKEY_SIZE);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear all struct members
        /// </summary>
        public void Reset()
        {
            MacCodeLength = 0;
            if (KeyID != null)
            {
                Array.Clear(KeyID, 0, KeyID.Length);
                KeyID = null;
            }
            if (Extension != null)
            {
                Array.Clear(Extension, 0, Extension.Length);
                Extension = null;
            }
        }

        /// <summary>
        /// Convert the MessageDescription structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the MessageDescription</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the MessageDescription structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the MessageDescription</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((short)MacCodeLength);
            writer.Write(KeyID, 0, KEYUID_SIZE);
            writer.Write(Extension, 0, EXTKEY_SIZE);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get decrypted file extension
        /// </summary>
        /// 
        /// <param name="Extension">The encrypted file extension</param>
        /// <param name="Key">Random byte array used to encrypt the extension</param>
        /// 
        /// <returns>File extension</returns>
        public static string DecryptExtension(byte[] Extension, byte[] Key)
        {
            byte[] data = new byte[16];
            char[] letters = new char[8];

            Buffer.BlockCopy(Extension, 0, data, 0, Extension.Length);

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Key[i];

            Buffer.BlockCopy(data, 0, letters, 0, 16);

            return new string(letters).Replace("\0", String.Empty);
        }

        /// <summary>
        /// Encrypt the file extension
        /// </summary>
        /// 
        /// <param name="Extension">The message file extension</param>
        /// <param name="Key">Random byte array used to encrypt the extension</param>
        /// 
        /// <returns>Encrypted file extension</returns>
        public static byte[] EncryptExtension(string Extension, byte[] Key)
        {
            byte[] data = new byte[16];
            char[] letters = Extension.ToCharArray();
            int len = letters.Length * 2;

            Buffer.BlockCopy(letters, 0, data, 0, len);

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Key[i];

            return data;
        }

        /// <summary>
        /// Get the file extension key
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>The 16 byte extension field</returns>
        public static byte[] GetExtension(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_EXTKEY, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadBytes(EXTKEY_SIZE);
        }

        /// <summary>
        /// Get the size of a MessageDescription
        /// </summary>
        public static int GetHeaderSize { get { return SIZE_HDRBSE; } }

        /// <summary>
        /// Get the messages unique key identifier
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>The unique 16 byte ID of the key used to encrypt this message</returns>
        public static byte[] GetKeyId(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_KEYUID, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadBytes(KEYUID_SIZE);
        }

        /// <summary>
        /// Get the MAC value for this file
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>64 byte Hash value</returns>
        public static int GetMessageMacSize(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_MACLEN, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadInt16();
        }

        /// <summary>
        /// Test for valid header in file
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
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
        /// Set the messages 16 byte Key ID value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="Extension">The message file extension</param>
        public static void SetExtension(Stream MessageStream, byte[] Extension)
        {
            MessageStream.Seek(SEEKTO_EXTKEY, SeekOrigin.Begin);
            MessageStream.Write(Extension, 0, EXTKEY_SIZE);
        }

        /// <summary>
        /// Set the messages 16 byte Key ID value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="KeyID">The unique 16 byte ID of the key used to encrypt this message</param>
        public static void SetKeyId(Stream MessageStream, byte[] KeyID)
        {
            MessageStream.Seek(SEEKTO_KEYUID, SeekOrigin.Begin);
            MessageStream.Write(KeyID, 0, KEYUID_SIZE);
        }

        /// <summary>
        /// Set the messages MAC value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="MacLength">The Message Authentication Code length</param>
        public static void SetMessageMac(Stream MessageStream, int MacLength)
        {
            MessageStream.Seek(SEEKTO_MACLEN, SeekOrigin.Begin);
            new BinaryWriter(MessageStream).Write((short)MacLength);
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
            int hash = ArrayUtils.GetHashCode(KeyID);
            hash += ArrayUtils.GetHashCode(Extension);
            hash += MacCodeLength;

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
            if (!(Obj is MessageDescription))
                return false;

            MessageDescription other = (MessageDescription)Obj;

            if (MacCodeLength != other.MacCodeLength)
                return false;
            if (!Compare.IsEqual(KeyID, other.KeyID))
                return false;
            if (!Compare.IsEqual(Extension, other.Extension))
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
        public static bool operator ==(MessageDescription X, MessageDescription Y)
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
        public static bool operator !=(MessageDescription X, MessageDescription Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
}
