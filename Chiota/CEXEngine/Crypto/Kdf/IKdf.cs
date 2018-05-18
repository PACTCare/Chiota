using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;

namespace VTDev.Libraries.CEXEngine.Crypto.Kdf
{
    public interface IKdf : IDisposable
    {
        /// <summary>
        /// Get: The generators type name
        /// </summary>
        Kdfs Enumeral { get; }

        /// <summary>
        /// Get: Generator is ready to produce random
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Minimum recommended initialization key size in bytes.
        /// <para>Combined sizes of key, salt, and info should be at least this size.</para></para>
        /// </summary>
        int MinKeySize { get; }

        /// <summary>
        /// Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Generate a block of pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// 
        /// <returns>The number of bytes generated</returns>
        int Generate(byte[] Output);

        /// <summary>
        /// Generate pseudo random bytes using offset and length parameters
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">The starting position within the Output array</param>
        /// <param name="Length">The number of bytes to generate</param>
        /// 
        /// <returns>The number of bytes generated</returns>
        int Generate(byte[] Output, int OutOffset, int Length);

	    /// <summary>
	    /// Initialize the generator with a MacParams structure containing the key and optional salt (IV) and info string (IKM)
	    /// </summary>
	    /// 
	    /// <param name="GenParam">The MacParams containing the generators keying material</param>
	    void Initialize(MacParams GenParam);

        /// <summary>
        /// Initialize the generator with a key
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        void Initialize(byte[] Key);

        /// <summary>
        /// Initialize the generator with key and salt arrays
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value containing an additional source of entropy</param>
        void Initialize(byte[] Key, byte[] Salt);

        /// <summary>
        /// Initialize the generator with a key, a salt array, and an information string or nonce
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value used as an additional source of entropy</param>
        /// <param name="Info">The information string or nonce used as a third source of entropy</param>
        void Initialize(byte[] Key, byte[] Salt, byte[] Info);

        /// <summary>
        /// Update the generators keying material
        /// </summary>
        ///
        /// <param name="Seed">The new seed value array</param>
        void Update(byte[] Seed);
    }
}
