#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/> subkey policy flags describing the current state of that subkey set.
    /// <para>Used by the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory"/> class to set a subkey operational state flag.</para>
    /// </summary>
    [Flags]
    public enum PackageKeyStates : long
    {
        /// <summary>
        /// The subkey set is no longer valid for encryption
        /// </summary>
        Expired = 1,
        /// <summary>
        /// The subkey was set to the PostOverwrite policy and has been used for decryption and subsequently erased
        /// </summary>
        Erased = 2,
        /// <summary>
        /// The subkey was set to the SingleUse policy and has been used for decryption and subsequently locked for access
        /// </summary>
        Locked = 4,
        /// <summary>
        /// An action has caused the erasure of the entire subkey set array
        /// </summary>
        Destroyed = 8
    }
}
