#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing a forward and return session key pairing.
    /// </summary>
    public class DtmKeySynchronizedArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The <see cref="DtmForwardKeyStruct"/> containing the forward (transmit) session key and decription
        /// </summary>
        public DtmForwardKeyStruct ForwardKey;
        /// <summary>
        /// The <see cref="DtmForwardKeyStruct"/> containing the forward (receive) session key and decription
        /// </summary>
        public DtmForwardKeyStruct ReturnKey;
        /// <summary>
        /// The Cancel token; setting this value to true instructs the server to disconnect
        /// </summary>
        public bool Cancel = false;
        #endregion

        #region Constructor
        /// <summary>
        /// The session key received event args constructor
        /// </summary>
        /// 
        /// <param name="ForwardKey">The <see cref="DtmForwardKeyStruct"/> containing the forward (transmit) session key and decription</param>
        /// <param name="ReturnKey">The <see cref="DtmForwardKeyStruct"/> containing the forward (receive) session key and decription</param>
        public DtmKeySynchronizedArgs(DtmForwardKeyStruct ForwardKey, DtmForwardKeyStruct ReturnKey)
        {
            this.ForwardKey = ForwardKey;
            this.ReturnKey = ReturnKey;
            this.Cancel = false;
        }
        #endregion
    }
}
