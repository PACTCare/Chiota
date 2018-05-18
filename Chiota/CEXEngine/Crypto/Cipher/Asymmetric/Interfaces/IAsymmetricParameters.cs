#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// The Asymmetric parameters interface
    /// </summary>
    public interface IAsymmetricParameters : ICloneable, IDisposable
    {
        /// <summary>
        /// Get: The parameters name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Returns the current parameter set as an ordered byte array
        /// </summary>
        /// 
        /// <returns>Parameters as a byte array</returns>
        byte[] ToBytes();

        /// <summary>
        /// Returns the current parameter set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>Parameters as a MemoryStream</returns>
        MemoryStream ToStream();

        /// <summary>
        /// Writes the parameter set to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">Parameters as a byte array; can be initialized as zero bytes</param>
        void WriteTo(byte[] Output);

        /// <summary>
        /// Writes the parameter set to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">Parameters as a byte array; array must be initialized and of sufficient length</param>
        /// <param name="Offset">The starting position within the Output array</param>
        void WriteTo(byte[] Output, int Offset);

        /// <summary>
        /// Writes the parameter set to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output stream</param>
        void WriteTo(Stream Output);
    }
}
