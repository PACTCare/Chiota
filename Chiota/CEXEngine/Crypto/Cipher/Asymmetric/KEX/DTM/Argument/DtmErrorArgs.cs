#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing the error state information.
    /// </summary>
    public class DtmErrorArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The DtmServiceFlags Exchange State (Auth or Primary), from which this message originated
        /// </summary>
        public Exception Message;
        /// <summary>
        /// The <see cref="DtmErrorSeverityFlags"/> flag indicating the operational impact of the error
        /// </summary>
        public DtmErrorSeverityFlags Severity;
        /// <summary>
        /// The Cancel token; setting this value to true instructs the server to shutdown the exchange (Terminate)
        /// </summary>
        public bool Cancel = false;
        #endregion

        #region Constructor
        /// <summary>
        /// The DTM error event args constructor; contains the current error state
        /// </summary>
        /// 
        /// <param name="Message">The <see cref="Exception"/></param>
        /// <param name="Severity">The <see cref="DtmErrorSeverityFlags"/> flag indicating the operational impact of the error</param>
        public DtmErrorArgs(Exception Message, DtmErrorSeverityFlags Severity)
        {
            this.Message = Message;
            this.Severity = Severity;
            this.Cancel = false;
        }
        #endregion
    }
}
