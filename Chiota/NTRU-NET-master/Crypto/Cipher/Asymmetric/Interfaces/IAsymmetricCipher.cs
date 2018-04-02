#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// The Asymmetric cipher interface
    /// </summary>
    public interface IAsymmetricCipher : IDisposable
    {
        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        int MaxPlainText { get; }

        /// <summary>
        /// Get: The ciphers name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the Key for Encrypt (Public) or Decrypt (Private)
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the Public (encrypt) or Private (decryption) key</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if an invalid key is used</exception>
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
