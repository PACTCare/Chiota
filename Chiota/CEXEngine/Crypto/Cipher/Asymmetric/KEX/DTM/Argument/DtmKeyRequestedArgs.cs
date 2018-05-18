#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
#endregion
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument
{
    /// <summary>
    /// An event arguments class containing the forward key parameters.
    /// </summary>
    public class DtmKeyRequestedArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// A flag indicating a special handling instruction
        /// </summary>
        public short Instruction;
        /// <summary>
        /// The time (in seconds, milliseconds, or ticks) that this key is to be considered valid
        /// </summary>
        public long LifeSpan;
        /// <summary>
        /// Can be additonal information; like a 'valid from' UTC time stamp
        /// </summary>
        public long OptionsFlag;
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
        /// <param name="Instruction">A flag indicating a special handling instruction</param>
        /// <param name="LifeSpan">The time (in seconds, milliseconds, or ticks) that this key is to be considered valid</param>
        /// <param name="OptionsFlag">Can be additonal information; like a 'valid from' UTC time stamp</param>
        public DtmKeyRequestedArgs(short Instruction = 0, long LifeSpan = 0, long OptionsFlag = 0)
        {
            this.LifeSpan = LifeSpan;
            this.Instruction = Instruction;
            this.OptionsFlag = OptionsFlag;
            this.Cancel = false;
        }
        #endregion
    }
}
