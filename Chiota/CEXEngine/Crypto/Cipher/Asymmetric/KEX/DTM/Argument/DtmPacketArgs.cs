#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing the exchange state information.
    /// </summary>
    public class DtmPacketArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The DtmServiceFlags Exchange State  (Auth or Primary), from which this message originated
        /// </summary>
        public short Message = 1;
        /// <summary>
        /// The option flag containing optional state information
        /// </summary>
        public long OptionFlag = 0;
        /// <summary>
        /// The Cancel token; setting this value to true instructs the server to shutdown the exchange (Terminate)
        /// </summary>
        public bool Cancel = false;
        #endregion

        #region Constructor
        /// <summary>
        /// The DTM packet event args constructor; contains the current exchange state
        /// </summary>
        /// 
        /// <param name="Message">The DtmServiceFlags Exchange State (Auth or Primary), from which this message originated</param>
        /// <param name="OptionFlag">The option flag containing optional state information</param>
        public DtmPacketArgs(short Message, long OptionFlag)
        {
            this.Message = Message;
            this.OptionFlag = OptionFlag;
            this.Cancel = false;
        }
        #endregion
    }
}
