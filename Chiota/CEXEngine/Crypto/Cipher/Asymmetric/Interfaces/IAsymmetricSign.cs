#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// The Asymmetric cipher interface
    /// </summary>
    public interface IAsymmetricSign : IDisposable
    {
        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Get: This class is initialized for Signing with the Private key
        /// </summary>
        bool IsSigner { get; }

        /// <summary>
        /// Get: The Signer name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the Key for Sign (Private) or Verify (Public)
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the Public (verify) or Private (sign) key</param>
        void Initialize(IAsymmetricKey AsmKey);

        /// <summary>
        /// Reset the underlying engine
        /// </summary>
        void Reset();

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        byte[] Sign(Stream InputStream);

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="Input">The byte array contining the data</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        byte[] Sign(byte[] Input, int Offset, int Length);

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data to test</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        bool Verify(Stream InputStream, byte[] Code);

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="Input">The stream containing the data to test</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        bool Verify(byte[] Input, int Offset, int Length, byte[] Code);
    }
}
