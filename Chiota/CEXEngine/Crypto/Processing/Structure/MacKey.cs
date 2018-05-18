#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    /// <summary>
    /// The MacKey structure.
    /// <para>Used in conjunction with the <see cref="MacStream"/> class. 
    /// This structure is used as the header for a Mac key file.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a MacKey structure:</description>
    /// <code>
    /// MacKey mk = new MacKey(MacDescription, [Keyid]);
    /// </code>
    /// </example>
    ///
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.MacDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.MacStream"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct MacKey
    {
        #region Constants
        private const int MACDSC_SIZE = 10;
        private const int KEYUID_SIZE = 16;
        private const int MACKEY_SIZE = 16;
        private const long MACDSC_SEEK = 0;
        private const long KEYUID_SEEK = MACDSC_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.MacDescription">MacDescription</see> structure containing a complete description of the Mac instance
        /// </summary>
        [MarshalAs(UnmanagedType.Struct, SizeConst = MACDSC_SIZE)]
        public MacDescription Description;
        /// <summary>
        /// The unique 16 byte ID field used to identify this key. A null value auto generates this field
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = KEYUID_SIZE)]
        public byte[] KeyId;
        #endregion

        #region Constructor
        /// <summary>
        /// MacKey structure constructor.
        /// <para>KeyID and ExtRandom values must each be 16 bytes in length.
        /// If they are not specified they will be populated automatically.</para>
        /// </summary>
        /// 
        /// <param name="Description">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.MacDescription">MacDescription</see> structure containing a complete description of the cipher instance</param>
        /// <param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if either the KeyId or ExtensionKey fields are null or invalid</exception>
        public MacKey(MacDescription Description, byte[] KeyId = null)
        {
            this.Description = Description;

            if (KeyId == null)
            {
                this.KeyId = Guid.NewGuid().ToByteArray();
            }
            else if (KeyId.Length != KEYUID_SIZE)
            {
                throw new CryptoProcessingException("MacKey:CTor", "The KeyId must be exactly 16 bytes!", new ArgumentOutOfRangeException());
            }
            else
            {
                this.KeyId = KeyId;
            }
        }

        /// <summary>
        /// Initialize the MacKey structure using a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The Stream containing the MacKey</param>
        public MacKey(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            Description = new MacDescription(reader.ReadBytes(MacDescription.GetHeaderSize()));
            KeyId = reader.ReadBytes(KEYUID_SIZE);
        }

        /// <summary>
        /// Initialize the MacKey structure using a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the MacKey</param>
        public MacKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Reset all members of the MacKey structure, including the MacDescription
        /// </summary>
        public void Reset()
        {
            Description.Reset();

            if (KeyId != null)
                Array.Clear(KeyId, 0, KeyId.Length);
        }

        /// <summary>
        /// Convert the MacKey structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the MacKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the MacKey structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the MacKey</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Description.ToBytes());
            writer.Write(KeyId);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return MACKEY_SIZE;
        }

        /// <summary>
        /// Get the cipher description header
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>MacDescription structure</returns>
        public static MacDescription GetCipherDescription(Stream KeyStream)
        {
            KeyStream.Seek(MACDSC_SEEK, SeekOrigin.Begin);
            return new MacDescription(KeyStream);
        }

        /// <summary>
        /// Get the key id (16 bytes)
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a cipher key</param>
        /// 
        /// <returns>The file extension key</returns>
        public static byte[] GetKeyId(Stream KeyStream)
        {
            KeyStream.Seek(KEYUID_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadBytes(KEYUID_SIZE);
        }
        #endregion

        #region Setters
        /// <summary>
        /// Set the MacDescription structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Description">The MacDescription structure</param>
        public static void SetCipherDescription(Stream KeyStream, MacDescription Description)
        {
            KeyStream.Seek(MACDSC_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Description.ToBytes());
        }

        /// <summary>
        /// Set the Key Id
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a cipher key</param>
        /// <param name="KeyId">Array of 16 bytes containing the key id</param>
        public static void SetKeyId(Stream KeyStream, byte[] KeyId)
        {
            byte[] id = new byte[KEYUID_SIZE];
            Array.Copy(KeyId, 0, id, 0, KeyId.Length < KEYUID_SIZE ? KeyId.Length : KEYUID_SIZE);
            KeyStream.Seek(KEYUID_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(id);
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
            int hash = Description.GetHashCode();
            hash += KeyId.GetHashCode();

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
            if (!(Obj is MacKey))
                return false;

            MacKey other = (MacKey)Obj;

            if (Description.GetHashCode() != other.Description.GetHashCode())
                return false;
            if (!Compare.IsEqual(KeyId, other.KeyId))
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
        public static bool operator ==(MacKey X, MacKey Y)
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
        public static bool operator !=(MacKey X, MacKey Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
}
