namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Message Digests
    /// </summary>
    public enum Digests : int
    {
        /// <summary>
        /// The Blake digest with a 256 bit return size
        /// </summary>
        Blake256 = 0,
        /// <summary>
        /// The Blake digest with a 512 bit return size
        /// </summary>
        Blake512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 256 bit return size
        /// </summary>
        Keccak256,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 512 bit return size
        /// </summary>
        Keccak512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 1024 bit return size
        /// </summary>
        Keccak1024,
        /// <summary>
        ///The SHA-2 digest with a 256 bit return size
        /// </summary>
        SHA256,
        /// <summary>
        /// The SHA-2 digest with a 512 bit return size
        /// </summary>
        SHA512,
        /// <summary>
        /// The Skein digest with a 256 bit return size
        /// </summary>
        Skein256,
        /// <summary>
        /// The Skein digest with a 512 bit return size
        /// </summary>
        Skein512,
        /// <summary>
        /// The Skein digest with a 1024 bit return size
        /// </summary>
        Skein1024
    }
}
