#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// The Seed Generator interface
    /// </summary>
    public interface ISeed : IDisposable
    {
        /// <summary>
        /// Get: Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Get a pseudo random seed byte array
        /// </summary>
        /// 
        /// <param name="Size">The size of the seed returned; up to a maximum of 1024 bytes</param>
        /// 
        /// <returns>A pseudo random seed</returns>
        byte[] GetSeed(int Size);
    }
}
