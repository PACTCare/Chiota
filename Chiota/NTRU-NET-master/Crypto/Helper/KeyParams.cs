#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto
{
    /// <summary>
    /// A Cipher Key and Vector Container class.
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
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
