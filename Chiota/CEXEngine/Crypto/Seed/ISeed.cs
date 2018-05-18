#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// The Seed Generator interface
    /// </summary>
    public interface ISeed : IDisposable
    {
        /// <summary>
        /// Get: The generators type name
        /// </summary>
        SeedGenerators Enumeral { get; }

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
        byte[] GetBytes(int Size);

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">The destination array</param>
        void GetBytes(byte[] Output);

        /// <summary>
        /// Reset the state
        /// </summary>
        void Reset();
    }
}
