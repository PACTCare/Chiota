#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using System.Net.Sockets;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing the final symmetric keys from a completed exchange.
    /// </summary>
    public sealed class DtmEstablishedArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The established client socket instance
        /// </summary>
        public Socket Client;
        /// <summary>
        /// The initialized Forward session encryption cipher; used to encrypt a stream sent to the remote host
        /// </summary>
        public ICipherMode ForwardSession;
        /// <summary>
        /// The initialized Return session encryption cipher; used to decrypt a stream sent from the remote host
        /// </summary>
        public ICipherMode ReturnSession;
        /// <summary>
        /// An option flag that can contain additional information about the exchange
        /// </summary>
        public long OptionFlag = 0;
        #endregion

        #region Constructor
        /// <summary>
        /// The DTM Established event arguments constructor
        /// </summary>
        /// 
        /// <param name="Client">The established client socket instance</param>
        /// <param name="ForwardSession">The initialized Forward session encryption cipher; used to encrypt data sent to the remote host</param>
        /// <param name="ReturnSession">The initialized Return session encryption cipher; used to decrypt data sent from the remote host</param>
        /// <param name="Flag">An option flag that can contain additional information about the exchange</param>
        public DtmEstablishedArgs(Socket Client, ICipherMode ForwardSession, ICipherMode ReturnSession, long Flag)
        {
            this.Client = Client;
            this.ForwardSession = ForwardSession;
            this.ReturnSession = ReturnSession;
            this.OptionFlag = Flag;
        }
        #endregion
    }
}
