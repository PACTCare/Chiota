#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    /// <summary>
    /// A Cipher Key and Vector Container class
    /// </summary>
    public class KeyParams : IDisposable
    {
        #region Fields
        private bool _isDisposed = false;
        private byte[] _Key = null;
        private byte[] _IV = null;
        private byte[] _IKM = null;
        #endregion

        #region Properties
        /// <summary>
        /// Input Key Material
        /// </summary>
        public byte[] IKM
        {
            get { return _IKM == null ? null : (byte[])_IKM.Clone(); }
            private set { _IKM = value; }
        }

        /// <summary>
        /// Cipher Key
        /// </summary>
        public byte[] Key 
        {
            get { return _Key == null ? null : (byte[])_Key.Clone(); } 
            private set { _Key = value; } 
        }

        /// <summary>
        /// Cipher Initialization Vector
        /// </summary>
        public byte[] IV 
        {
            get { return _IV == null ? null : (byte[])_IV.Clone(); }
            private set { _IV = value; } 
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class with a Cipher Key
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        public KeyParams(byte[] Key)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, Key.Length);
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
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, Key.Length);
            }
            if (IV != null)
            {
                _IV = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, _IV, 0, IV.Length);
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
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, Key.Length);
            }
            if (IV != null)
            {
                _IV = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, _IV, 0, IV.Length);
            }
            if (IKM != null)
            {
                _IKM = new byte[IKM.Length];
                Buffer.BlockCopy(IKM, 0, _IKM, 0, IKM.Length);
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
            byte[] key = null;
            byte[] iv = null;
            byte[] ikm = null;

            if (keyLen > 0)
                key = reader.ReadBytes(keyLen);
            if (ivLen > 0)
                iv = reader.ReadBytes(ivLen);
            if (ikmLen > 0)
                ikm = reader.ReadBytes(ikmLen);

            return new KeyParams(key, iv, ikm);
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

            if (KeyObj.Key != null)
                writer.Write(KeyObj.Key);
            if (KeyObj.IV != null)
                writer.Write(KeyObj.IV);
            if (KeyObj.IKM != null)
                writer.Write(KeyObj.IKM);

            return stream;
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_Key != null)
                    {
                        Array.Clear(_Key, 0, _Key.Length);
                        _Key = null;
                    }

                    if (_IV != null)
                    {
                        Array.Clear(_IV, 0, _IV.Length);
                        _IV = null;
                    }
                    if (_IKM != null)
                    {
                        Array.Clear(_IKM, 0, _IKM.Length);
                        _IKM = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
