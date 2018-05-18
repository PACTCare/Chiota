#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing the identity of a client.
    /// </summary>
    public sealed class DtmIdentityArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The <see cref="DtmServiceFlags"/> (Auth or Primary), from which this message originated
        /// </summary>
        public DtmExchangeFlags Message = DtmExchangeFlags.Init;
        /// <summary>
        /// The option flag containing the clients proposed Asymmetric parameters OId
        /// </summary>
        public long Flag = 0;
        /// <summary>
        /// The <see cref="DtmIdentityStruct"/> containing identity and session parameters
        /// </summary>
        public DtmIdentityStruct DtmID;
        /// <summary>
        /// The Cancel token; setting this value to true instructs the server to shutdown the exchange (Terminate)
        /// </summary>
        public bool Cancel = false;
        #endregion

        #region Constructor
        /// <summary>
        /// The identity exchanged event args constructor; contains the identity and Asymmetric parameters OId from an Identity structure
        /// </summary>
        /// 
        /// <param name="Message">The <see cref="DtmServiceFlags"/> (Auth or Primary), from which this message originated</param>
        /// <param name="Flag">An option flag that contains the clients Asymmetric parameters OId</param>
        /// <param name="DtmID">The <see cref="DtmIdentityStruct"/> containing identity and session parameters</param>
        public DtmIdentityArgs(DtmExchangeFlags Message, long Flag, DtmIdentityStruct DtmID)
        {
            this.Message = Message;
            this.Flag = Flag;
            this.DtmID = DtmID;
            this.Cancel = false;
        }
        #endregion
    }
}
