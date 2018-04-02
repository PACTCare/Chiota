#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// Random Generator Interface
    /// </summary>
    public interface IGenerator : IDisposable
    {
        /// <summary>
        /// Get: Generator is ready to produce data
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// <para>Minimum initialization key size in bytes; 
        /// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt is used</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Salt does not contain enough material for Key and Vector creation</exception>
        void Initialize(byte[] Salt);

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt or Ikm is used</exception>
        void Initialize(byte[] Salt, byte[] Ikm);

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Nonce">Nonce value</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt is used</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Salt does not contain enough material for Key and Vector creation</exception>
        void Initialize(byte[] Salt, byte[] Ikm, byte[] Nonce);

        /// <summary>
        /// Generate a block of pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        int Generate(byte[] Output);

        /// <summary>
        /// Generate pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        int Generate(byte[] Output, int OutOffset, int Size);

        /// <summary>
        /// Update the Seed material
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Seed is used</exception>
        void Update(byte[] Seed);
    }
}
