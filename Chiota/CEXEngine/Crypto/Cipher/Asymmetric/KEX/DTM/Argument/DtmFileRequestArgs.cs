#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing the FileRequest state
    /// </summary>
    public class DtmFileRequestArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// Fires with the name of the file; returns the destination folder
        /// </summary>
        public string FilePath = string.Empty;
        /// <summary>
        /// The option flag containing optional state information
        /// </summary>
        public long OptionFlag = 0;
        /// <summary>
        /// The Cancel token; setting this value to true instructs the server to refuse the file
        /// </summary>
        public bool Cancel = false;
        #endregion

        #region Constructor
        /// <summary>
        /// The DTM packet event args constructor; contains the file request state
        /// </summary>
        /// 
        /// <param name="FilePath">Fires with the name of the file; returns the destination folder</param>
        /// <param name="OptionFlag">The option flag containing optional state information</param>
        public DtmFileRequestArgs(string FilePath = "", long OptionFlag = 0)
        {
            this.FilePath = FilePath;
            this.OptionFlag = OptionFlag;
            this.Cancel = false;
        }
        #endregion
    }
}
