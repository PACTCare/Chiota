#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// KeyParams: A Symmetric Cipher Key and Vector Container class.
    /// </summary>
    public class KeyParams : IDisposable, ICloneable
    {
        #region Fields
        private bool m_isDisposed = false;
        private byte[] m_Key = null;
        private byte[] m_Iv = null;
        private byte[] m_Ikm = null;
        private byte[] m_extKey = null;
        #endregion

        #region Properties
        /// <summary>
        /// Input Key Material
        /// </summary>
        public byte[] IKM
        {
            get { return m_Ikm == null ? null : (byte[])m_Ikm.Clone(); }
            set { m_Ikm = value; }
        }

        /// <summary>
        /// Cipher Key
        /// </summary>
        public byte[] Key 
        {
            get { return m_Key == null ? null : (byte[])m_Key.Clone(); } 
            set { m_Key = value; } 
        }

        /// <summary>
        /// Cipher Initialization Vector
        /// </summary>
        public byte[] IV 
        {
            get { return m_Iv == null ? null : (byte[])m_Iv.Clone(); }
            set { m_Iv = value; } 
        }

        /// <summary>
        /// Extended key material
        /// </summary>
        public byte[] ExtKey
        {
            get { return m_extKey == null ? null : (byte[])m_extKey.Clone(); }
            set { m_extKey = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize an empty container
        /// </summary>
        public KeyParams()
        {
        }

        /// <summary>
        /// Initialize the class with a Cipher Key
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        public KeyParams(byte[] Key)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
        }

        /// <summary>
        /// Initialize the class with a Cipher Key and IV.
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        public KeyParams(byte[] Key, byte[] IV)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
            if (IV != null)
            {
                m_Iv = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, m_Iv, 0, m_Iv.Length);
            }
        }

        /// <summary>
        /// Initialize the class with a Cipher Key, IV, and IKM.
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        /// <param name="IKM">IKM value</param>
        public KeyParams(byte[] Key, byte[] IV, byte[] IKM)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
            if (IV != null)
            {
                m_Iv = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, m_Iv, 0, m_Iv.Length);
            }
            if (IKM != null)
            {
                m_Ikm = new byte[IKM.Length];
                Buffer.BlockCopy(IKM, 0, m_Ikm, 0, m_Ikm.Length);
            }
        }

        /// <summary>
        /// Initialize the class with a Cipher Key, IV, IKM, and ExtKey
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        /// <param name="IKM">IKM value</param>
        /// <param name="ExtKey">ExtKey value</param>
        public KeyParams(byte[] Key, byte[] IV, byte[] IKM, byte[] ExtKey)
        {
            if (Key != null)
            {
                m_Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, m_Key, 0, m_Key.Length);
            }
            if (IV != null)
            {
                m_Iv = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, m_Iv, 0, m_Iv.Length);
            }
            if (IKM != null)
            {
                m_Ikm = new byte[IKM.Length];
                Buffer.BlockCopy(IKM, 0, m_Ikm, 0, m_Ikm.Length);
            }
            if (ExtKey != null)
            {
                m_extKey = new byte[ExtKey.Length];
                Buffer.BlockCopy(ExtKey, 0, m_extKey, 0, m_extKey.Length);
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~KeyParams()
        {
            Dispose(false);
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize a KeyParams class
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing the KeyParams data</param>
        /// 
        /// <returns>A populated KeyParams class</returns>
        public static KeyParams DeSerialize(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            short keyLen = reader.ReadInt16();
            short ivLen = reader.ReadInt16();
            short ikmLen = reader.ReadInt16();
            short extLen = reader.ReadInt16();

            byte[] key = null;
            byte[] iv = null;
            byte[] ikm = null;
            byte[] ext = null;

            if (keyLen > 0)
                key = reader.ReadBytes(keyLen);
            if (ivLen > 0)
                iv = reader.ReadBytes(ivLen);
            if (ikmLen > 0)
                ikm = reader.ReadBytes(ikmLen);
            if (extLen > 0)
                ext = reader.ReadBytes(extLen);

            return new KeyParams(key, iv, ikm, ext);
        }

        /// <summary>
        /// Serialize a KeyParams class
        /// </summary>
        /// 
        /// <param name="KeyObj">A KeyParams class</param>
        /// 
        /// <returns>A stream containing the KeyParams data</returns>
        public static Stream Serialize(KeyParams KeyObj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(KeyObj.Key != null ? (short)KeyObj.Key.Length : (short)0);
            writer.Write(KeyObj.IV != null ? (short)KeyObj.IV.Length : (short)0);
            writer.Write(KeyObj.IKM != null ? (short)KeyObj.IKM.Length : (short)0);
            writer.Write(KeyObj.ExtKey != null ? (short)KeyObj.ExtKey.Length : (short)0);

            if (KeyObj.Key != null)
                writer.Write(KeyObj.Key);
            if (KeyObj.IV != null)
                writer.Write(KeyObj.IV);
            if (KeyObj.IKM != null)
                writer.Write(KeyObj.IKM);
            if (KeyObj.ExtKey != null)
                writer.Write(KeyObj.ExtKey);

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
            writer.Write(m_Iv != null ? (short)m_Iv.Length : (short)0);
            writer.Write(m_Ikm != null ? (short)m_Ikm.Length : (short)0);
            writer.Write(m_extKey != null ? (short)m_extKey.Length : (short)0);

            if (m_Key != null)
                writer.Write(m_Key);
            if (m_Iv != null)
                writer.Write(m_Iv);
            if (m_Ikm != null)
                writer.Write(m_Ikm);
            if (m_extKey != null)
                writer.Write(m_extKey);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region ICloneable
        /// <summary>
        /// Create a shallow copy of this KeyParams instance
        /// </summary>
        /// 
        /// <returns>The KeyParams copy</returns>
        public object Clone()
        {
            return new KeyParams(m_Key, m_Iv, m_Ikm, m_extKey);
        }

        /// <summary>
        /// Create a deep copy of this KeyParams instance
        /// </summary>
        /// 
        /// <returns>The KeyParams copy</returns>
        public object DeepCopy()
        {
            return DeSerialize(Serialize(this));
        }
        #endregion

        #region Equals
        /// <summary>
        /// Compare this KeyParams instance with another
        /// </summary>
        /// 
        /// <param name="Obj">KeyParams to compare</param>
        /// 
        /// <returns>Returns true if equal</returns>
        public bool Equals(KeyParams Obj)
        {
            if (!Compare.IsEqual(Obj.Key, m_Key))
                return false;
            if (!Compare.IsEqual(Obj.IV, m_Iv))
                return false;
            if (!Compare.IsEqual(Obj.IKM, m_Ikm))
                return false;
            if (!Compare.IsEqual(Obj.ExtKey, m_extKey))
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
            int hash =  Utility.ArrayUtils.GetHashCode(m_Key);
            hash += Utility.ArrayUtils.GetHashCode(m_Iv);
            hash += Utility.ArrayUtils.GetHashCode(m_Ikm);
            hash += Utility.ArrayUtils.GetHashCode(m_extKey);

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

                    if (m_Iv != null)
                    {
                        Array.Clear(m_Iv, 0, m_Iv.Length);
                        m_Iv = null;
                    }
                    if (m_Ikm != null)
                    {
                        Array.Clear(m_Ikm, 0, m_Ikm.Length);
                        m_Ikm = null;
                    }
                    if (m_extKey != null)
                    {
                        Array.Clear(m_extKey, 0, m_extKey.Length);
                        m_extKey = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
