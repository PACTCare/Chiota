#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// Cipher Mode Interface
    /// </summary>
    public interface ICipherMode : IDisposable
    {
        /// <summary>
        /// Get: Unit block size of internal cipher
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Get: Underlying Cipher
        /// </summary>
        IBlockCipher Engine { get; }

        /// <summary>
        /// Get: Initialized for encryption, false for decryption
        /// </summary>
        bool IsEncryption { get; }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Get: The current state of the initialization Vector
        /// </summary>
        byte[] IV { get; }

        /// <summary>
        /// Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key and Vector</param>
        void Initialize(bool Encryption, KeyParams KeyParam);

        /// <summary>
        /// Transform a block of bytes
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Transform a block of bytes within an array
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset);
    }
}
