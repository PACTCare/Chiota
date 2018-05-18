#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// MacParams: A MAC Key, Salt, and Info Container class.
    /// </summary>
    public sealed class MacParams
    {
        #region Fields
        bool m_isDisposed;
        byte[] m_Key;
        byte[] m_Info;
        byte[] m_Salt;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: The MAC Key
        /// </summary>
        public byte[] Key
        {
            get { return m_Key == null ? null : (byte[])m_Key.Clone(); }
            set { m_Key = value; }
        }

        /// <summary>
        /// Get/Set: MAC Personalization info
        /// </summary>
        public byte[] Info
        {
            get { return m_Info == null ? null : (byte[])m_Info.Clone(); }
            set { m_Info = value; }
        }

        /// <summary>
        /// Get/Set: MAC Salt value
        /// </summary>
        public byte[] Salt
        {
            get { return m_Salt == null ? null : (byte[])m_Salt.Clone(); }
            set { m_Salt = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public MacParams()
        {
            m_isDisposed = false;
        }

        /// <summary>
        /// Initialize this class with a MAC Key
        /// </summary>
        ///
        /// <param name="Key">MAC Key</param>
        public MacParams(byte[] Key)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
        }

        /// <summary>
        /// Initialize this class with a MAC Key, and Salt
        /// </summary>
        ///
        /// <param name="Key">MAC Key</param>
        /// <param name="Salt">MAC Salt</param>
        public MacParams(byte[] Key, byte[] Salt)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
            if (Salt != null)
            {
                m_Salt = new byte[Salt.Length];
                Buffer.BlockCopy(Salt, 0, m_Salt, 0, Salt.Length);
            }
        }

        /// <summary>
        /// Initialize this class with a Cipher Key, Salt, and Info
        /// </summary>
        ///
        /// <param name="Key">MAC Key</param>
        /// <param name="Salt">MAC Salt</param>
        /// <param name="Info">MAC Info</param>
        public MacParams(byte[] Key, byte[] Salt, byte[] Info)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
            if (Salt != null)
            {
                m_Salt = new byte[Salt.Length];
                Buffer.BlockCopy(Salt, 0, m_Salt, 0, Salt.Length);
            }
            if (Info != null)
            {
                m_Info = new byte[Info.Length];
                Buffer.BlockCopy(Info, 0, m_Info, 0, Info.Length);
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MacParams()
        {
            Dispose();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize a MacParams class
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing the MacParams data</param>
        /// 
        /// <returns>A populated MacParams class</returns>
        public static MacParams DeSerialize(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            short keyLen = reader.ReadInt16();
            short saltLen = reader.ReadInt16();
            short infoLen = reader.ReadInt16();

            byte[] key = null;
            byte[] salt = null;
            byte[] info = null;

            if (keyLen > 0)
                key = reader.ReadBytes(keyLen);
            if (saltLen > 0)
                salt = reader.ReadBytes(saltLen);
            if (infoLen > 0)
                info = reader.ReadBytes(infoLen);

            return new MacParams(key, salt, info);
        }

        /// <summary>
        /// Serialize a MacParams class
        /// </summary>
        /// 
        /// <param name="MacObj">A MacParams class</param>
        /// 
        /// <returns>A stream containing the MacParams data</returns>
        public static Stream Serialize(MacParams MacObj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(MacObj.Key != null ? (short)MacObj.Key.Length : (short)0);
            writer.Write(MacObj.Salt != null ? (short)MacObj.Salt.Length : (short)0);
            writer.Write(MacObj.Info != null ? (short)MacObj.Info.Length : (short)0);

            if (MacObj.Key != null)
                writer.Write(MacObj.Key);
            if (MacObj.Salt != null)
                writer.Write(MacObj.Salt);
            if (MacObj.Info != null)
                writer.Write(MacObj.Info);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }

        /// <summary>
        /// Convert the Key parameters to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the keying material</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(m_Key != null ? (short)m_Key.Length : (short)0);
            writer.Write(m_Salt != null ? (short)m_Salt.Length : (short)0);
            writer.Write(m_Info != null ? (short)m_Info.Length : (short)0);

            if (m_Key != null)
                writer.Write(m_Key);
            if (m_Salt != null)
                writer.Write(m_Salt);
            if (m_Info != null)
                writer.Write(m_Info);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region ICloneable
        /// <summary>
        /// Create a shallow copy of this MacParams instance
        /// </summary>
        /// 
        /// <returns>The MacParams copy</returns>
        public object Clone()
        {
            return new MacParams(m_Key, m_Salt, m_Info);
        }

        /// <summary>
        /// Create a deep copy of this MacParams instance
        /// </summary>
        /// 
        /// <returns>The MacParams copy</returns>
        public object DeepCopy()
        {
            return DeSerialize(Serialize(this));
        }
        #endregion

        #region Equals
        /// <summary>
        /// Compare this MacParams instance with another
        /// </summary>
        /// 
        /// <param name="Obj">MacParams to compare</param>
        /// 
        /// <returns>Returns true if equal</returns>
        public bool Equals(MacParams Obj)
        {
            if (!Compare.IsEqual(Obj.Key, m_Key))
                return false;
            if (!Compare.IsEqual(Obj.Salt, m_Salt))
                return false;
            if (!Compare.IsEqual(Obj.Info, m_Info))
                return false;

            return true;
        }

        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = Utility.ArrayUtils.GetHashCode(m_Key);
            hash += Utility.ArrayUtils.GetHashCode(m_Salt);
            hash += Utility.ArrayUtils.GetHashCode(m_Info);

            return hash;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (m_Key != null)
                    {
                        Array.Clear(m_Key, 0, m_Key.Length);
                        m_Key = null;
                    }

                    if (m_Salt != null)
                    {
                        Array.Clear(m_Salt, 0, m_Salt.Length);
                        m_Salt = null;
                    }
                    if (m_Info != null)
                    {
                        Array.Clear(m_Info, 0, m_Info.Length);
                        m_Info = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    };
}
