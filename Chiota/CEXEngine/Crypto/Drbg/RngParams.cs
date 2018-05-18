#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Drbg
{
    /// <summary>
    /// RngParams: A DRBG Seed, Nonce, and Info Container class.
    /// </summary>
    public sealed class RngParams
    {
        #region Fields
        bool m_isDisposed;
        byte[] m_Info;
        byte[] m_Nonce;
        byte[] m_Seed;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: The primary generator seed key
        /// </summary>
        public byte[] Seed
        {
            get { return m_Seed == null ? null : (byte[])m_Seed.Clone(); }
            set { m_Seed = value; }
        }

        /// <summary>
        /// Get/Set: The personalization info, added as entropy or a distribution code
        /// </summary>
        public byte[] Info
        {
            get { return m_Info == null ? null : (byte[])m_Info.Clone(); }
            set { m_Info = value; }
        }

        /// <summary>
        /// Get/Set: The nonce value, added as an additional source of entropy
        /// </summary>
        public byte[] Nonce
        {
            get { return m_Nonce == null ? null : (byte[])m_Nonce.Clone(); }
            set { m_Nonce = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public RngParams()
        {
            m_isDisposed = false;
        }

        /// <summary>
        /// Initialize this class with the generator seed key
        /// </summary>
        ///
        /// <param name="Seed">MAC Seed</param>
        public RngParams(byte[] Seed)
        {
            if (Seed != null)
            {
                m_Seed = new byte[Seed.Length];
                Buffer.BlockCopy(Seed, 0, m_Seed, 0, m_Seed.Length);
            }
        }

        /// <summary>
        /// Initialize this class with a generator seed key, and nonce
        /// </summary>
        ///
        /// <param name="Seed">The primary generator seed key</param>
        /// <param name="Nonce">The nonce value, added as an additional source of entropy</param>
        public RngParams(byte[] Seed, byte[] Nonce)
        {
            if (Seed != null)
            {
                m_Seed = new byte[Seed.Length];
                Buffer.BlockCopy(Seed, 0, m_Seed, 0, m_Seed.Length);
            }
            if (Nonce != null)
            {
                m_Nonce = new byte[Nonce.Length];
                Buffer.BlockCopy(Nonce, 0, m_Nonce, 0, Nonce.Length);
            }
        }

        /// <summary>
        /// Initialize this class with a generator seed key, nonce, and info
        /// </summary>
        ///
        /// <param name="Seed">The primary generator seed key</param>
        /// <param name="Nonce">The nonce value, added as an additional source of entropy</param>
        /// <param name="Info">The personalization info, added as entropy or a distribution code</param>
        public RngParams(byte[] Seed, byte[] Nonce, byte[] Info)
        {
            if (Seed != null)
            {
                m_Seed = new byte[Seed.Length];
                Buffer.BlockCopy(Seed, 0, m_Seed, 0, m_Seed.Length);
            }
            if (Nonce != null)
            {
                m_Nonce = new byte[Nonce.Length];
                Buffer.BlockCopy(Nonce, 0, m_Nonce, 0, Nonce.Length);
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
        ~RngParams()
        {
            Dispose();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize a RngParams class
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing the RngParams data</param>
        /// 
        /// <returns>A populated RngParams class</returns>
        public static RngParams DeSerialize(Stream KeyStream)
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

            return new RngParams(key, salt, info);
        }

        /// <summary>
        /// Serialize a RngParams class
        /// </summary>
        /// 
        /// <param name="RngObj">A RngParams class</param>
        /// 
        /// <returns>A stream containing the RngParams data</returns>
        public static Stream Serialize(RngParams RngObj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(RngObj.Seed != null ? (short)RngObj.Seed.Length : (short)0);
            writer.Write(RngObj.Nonce != null ? (short)RngObj.Nonce.Length : (short)0);
            writer.Write(RngObj.Info != null ? (short)RngObj.Info.Length : (short)0);

            if (RngObj.Seed != null)
                writer.Write(RngObj.Seed);
            if (RngObj.Nonce != null)
                writer.Write(RngObj.Nonce);
            if (RngObj.Info != null)
                writer.Write(RngObj.Info);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }

        /// <summary>
        /// Convert the Seed parameters to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the keying material</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(m_Seed != null ? (short)m_Seed.Length : (short)0);
            writer.Write(m_Nonce != null ? (short)m_Nonce.Length : (short)0);
            writer.Write(m_Info != null ? (short)m_Info.Length : (short)0);

            if (m_Seed != null)
                writer.Write(m_Seed);
            if (m_Nonce != null)
                writer.Write(m_Nonce);
            if (m_Info != null)
                writer.Write(m_Info);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region ICloneable
        /// <summary>
        /// Create a shallow copy of this RngParams instance
        /// </summary>
        /// 
        /// <returns>The RngParams copy</returns>
        public object Clone()
        {
            return new RngParams(m_Seed, m_Nonce, m_Info);
        }

        /// <summary>
        /// Create a deep copy of this RngParams instance
        /// </summary>
        /// 
        /// <returns>The RngParams copy</returns>
        public object DeepCopy()
        {
            return DeSerialize(Serialize(this));
        }
        #endregion

        #region Equals
        /// <summary>
        /// Compare this RngParams instance with another
        /// </summary>
        /// 
        /// <param name="Obj">RngParams to compare</param>
        /// 
        /// <returns>Returns true if equal</returns>
        public bool Equals(RngParams Obj)
        {
            if (!Compare.IsEqual(Obj.Seed, m_Seed))
                return false;
            if (!Compare.IsEqual(Obj.Nonce, m_Nonce))
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
            int hash = Utility.ArrayUtils.GetHashCode(m_Seed);
            hash += Utility.ArrayUtils.GetHashCode(m_Nonce);
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
                    if (m_Seed != null)
                    {
                        Array.Clear(m_Seed, 0, m_Seed.Length);
                        m_Seed = null;
                    }

                    if (m_Nonce != null)
                    {
                        Array.Clear(m_Nonce, 0, m_Nonce.Length);
                        m_Nonce = null;
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
    }
}
