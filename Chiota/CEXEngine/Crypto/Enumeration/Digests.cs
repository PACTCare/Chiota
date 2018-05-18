namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Message Digests
    /// </summary>
    public enum Digests : int
    {
        /// <summary>
        /// No digest was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// The Blake2B digest with a 512 bit return size
        /// </summary>
        Blake2B512 = 1,
        /// <summary>
        /// The Blake2S digest with a 256 bit return size
        /// </summary>
        Blake2S256 = 3,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 256 bit return size
        /// </summary>
        Keccak256 = 5,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 512 bit return size
        /// </summary>
        Keccak512 = 6,
        /// <summary>
        ///The SHA-2 digest with a 256 bit return size
        /// </summary>
        SHA256 = 7,
        /// <summary>
        /// The SHA-2 digest with a 512 bit return size
        /// </summary>
        SHA512 = 8,
        /// <summary>
        /// The Skein digest with a 256 bit return size
        /// </summary>
        Skein256 = 9,
        /// <summary>
        /// The Skein digest with a 512 bit return size
        /// </summary>
        Skein512 = 10,
        /// <summary>
        /// The Skein digest with a 1024 bit return size
        /// </summary>
        Skein1024 = 11
    }
}
