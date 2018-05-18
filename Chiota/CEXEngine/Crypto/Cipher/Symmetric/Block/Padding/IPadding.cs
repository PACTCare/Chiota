using VTDev.Libraries.CEXEngine.Crypto.Enumeration;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// Padding Mode Interface
    /// </summary>
    public interface IPadding
    {
        /// <summary>
        /// Get: The cipher modes type name
        /// </summary>
        PaddingModes Enumeral { get; }

        /// <summary>
        /// Get: Padding name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Add padding to input array
        /// </summary>
        /// 
        /// <param name="Input">Array to modify</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        int AddPadding(byte[] Input, int Offset);

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// 
        /// <returns>Length of padding</returns>
        int GetPaddingLength(byte[] Input);

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        int GetPaddingLength(byte[] Input, int Offset);
    }
}
