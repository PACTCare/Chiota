#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream
{
    /// <summary>
    /// Stream Cipher Interface
    /// </summary>
    public interface IStreamCipher : IDisposable
    {
	    /// <summary>
	    /// Get: Unit block size of internal cipher in bytes.
	    /// <para>Block size must be 16 or 32 bytes wide. 
	    /// Value set in class constructor.</para>
	    /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Get: The stream ciphers type name
        /// </summary>
        StreamCiphers Enumeral { get; }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        bool IsParallel { get; set; }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        int[] LegalKeySizes { get; }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        int[] LegalRounds { get; }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        int ParallelBlockSize { get; set; }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        int ParallelMaximumSize { get; }

        /// <summary>
        /// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
        /// </summary>
        int ParallelMinimumSize { get; }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="KeyParam">Cipher key container. The LegalKeySizes property contains valid sizes</param>
        void Initialize(KeyParams KeyParam);

        /// <summary>
        /// Process an array of bytes.
        /// <para>This method processes the entire array; used when processing small data or buffers from a larger source.
        /// <see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Process a block of bytes using offset parameters.  
        /// <para>Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>. 
        /// This method will process a single block from the source array of either ParallelBlockSize or Blocksize depending on IsParallel property setting.
        /// Partial blocks are permitted with both parallel and linear operation modes.
        /// <see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if the input and output arrays do not align or are too small</exception>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Process an array of bytes using offset and length parameters.
        /// <para>This method processes a specified length of the array; used when processing segments of a large source array.
        /// Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>.
        /// This method automatically assigns the ParallelBlockSize as the Length divided by the number of processors.
        /// <see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        /// <param name="Length">Number of bytes to process</param>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length);
    }
}
