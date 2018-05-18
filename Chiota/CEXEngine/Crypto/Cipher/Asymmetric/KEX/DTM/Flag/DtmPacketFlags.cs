#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/> primary message types.
    /// </summary>
    public enum DtmPacketFlags : int
    {
        /// <summary>
        /// The packet contains a service instruction
        /// </summary>
        Service = 1,
        /// <summary>
        /// The packet contains message data
        /// </summary>
        Message = 2,
        /// <summary>
        /// The packet contains file transfer information
        /// </summary>
        Transfer = 4,
        /// <summary>
        /// The packet is part of a key exchange
        /// </summary>
        Exchange = 8,
        /// <summary>
        /// The packet contains key forwarding information
        /// </summary>
        Forwarding = 16
    }
}
