#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// Pseudo Random Number Generator Interface
    /// </summary>
    public interface IRandom : IDisposable
    {
        /// <summary>
        /// Get: The prngs type name
        /// </summary>
        Prngs Enumeral { get; }

        /// <summary>
        /// Get: Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Array to fill with random bytes</param>
        void GetBytes(byte[] Output);

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        byte[] GetBytes(int Size);

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
        int Next();

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random int</returns>
        int Next(int Maximum);

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random int</returns>
        int Next(int Minimum, int Maximum);

        /// <summary>
        /// Get a pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random long</returns>
        long NextLong();

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        long NextLong(long Maximum);

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        long NextLong(long Minimum, long Maximum);

        /// <summary>
        /// Reset the internal state
        /// </summary>
        void Reset();
    }
}
