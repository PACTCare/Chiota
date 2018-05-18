#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// McEliece cipher interface
    /// </summary>
    internal interface IMPKCCiphers : IDisposable
    {
        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        int MaxPlainText { get; }

        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="AsmKey">The public or private key</param>
        void Initialize(IAsymmetricKey AsmKey);

        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        byte[] Decrypt(byte[] Input);

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        byte[] Encrypt(byte[] Input);
    }
}
