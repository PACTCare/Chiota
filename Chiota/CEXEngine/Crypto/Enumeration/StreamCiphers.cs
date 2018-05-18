namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Stream Ciphers
    /// </summary>
    public enum StreamCiphers : int
    {
        /// <summary>
        /// No stream cipher was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// An implementation of the ChaCha Stream Cipher
        /// </summary>
        ChaCha = 8,
        /// <summary>
        /// A Salsa20 Stream Cipher
        /// </summary>
        Salsa = 16
    }
}
