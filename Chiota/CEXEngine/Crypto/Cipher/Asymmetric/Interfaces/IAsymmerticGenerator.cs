#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// The Asymmertic Generator interface
    /// </summary>
    public interface IAsymmetricGenerator : IDisposable
    {
        /// <summary>
        /// Get: The generators name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Generate an asymmetric Key pair
        /// </summary>
        /// 
        /// <returns>An asymmetric containing public and private keys</returns>
        IAsymmetricKeyPair GenerateKeyPair();
    }
}
