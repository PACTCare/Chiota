namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Stream Ciphers
    /// </summary>
    public enum StreamCiphers : int
    {
        /// <summary>
        /// An implementation of the ChaCha Stream Cipher
        /// </summary>
        ChaCha = 0,
        /// <summary>
        /// An implementation of the Twofish and Rijndael Merged Stream Cipher
        /// </summary>
        Fusion,
        /// <summary>
        /// A Salsa20 Stream Cipher
        /// </summary>
        Salsa
    }
}
