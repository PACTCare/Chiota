#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// Hash Digest Interface
    /// </summary>
    public interface IDigest : IDisposable
    {
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        int DigestSize { get; }

        /// <summary>
        /// Get: The Digest name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Update the buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        void BlockUpdate(byte[] Input, int InOffset, int Length);

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value</returns>
        byte[] ComputeHash(byte[] Input);

        /// <summary>
        /// Do final processing and get the hash value
        /// </summary>
        /// 
        /// <param name="Output">The Hash value container</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value</returns>
        int DoFinal(byte[] Output, int OutOffset);

        /// <summary>
        /// Reset the internal state
        /// </summary>
        void Reset();

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        void Update(byte Input);
    }
}
