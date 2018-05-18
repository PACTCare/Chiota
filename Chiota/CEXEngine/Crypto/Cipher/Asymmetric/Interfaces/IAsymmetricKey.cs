#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// The Asymmetric key interface
    /// </summary>
    public interface IAsymmetricKey : ICloneable, IDisposable
    {
        /// <summary>
        /// Converts the key pair to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key pair</returns>
        byte[] ToBytes();

        /// <summary>
        /// Returns the current key pair set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>KeyPair as a MemoryStream</returns>
        MemoryStream ToStream();

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        void WriteTo(byte[] Output);

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        /// <param name="Offset">The starting position within the Output array</param>
        void WriteTo(byte[] Output, int Offset);

        /// <summary>
        /// Writes the key pair to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output Stream</param>
        void WriteTo(Stream Output);
    }
}
