namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Cipher Modes
    /// </summary>
    public enum CipherModes : int
    {
        /// <summary>
        /// No cipher mode was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// Electronic CodeBook Mode (not secure, testing only)
        /// </summary>
        ECB = 1,
        /// <summary>
        /// Cipher Block Chaining Mode
        /// </summary>
        CBC = 2,
        /// <summary>
        /// Cipher FeedBack Mode
        /// </summary>
        CFB = 4,
        /// <summary>
        /// SIC Counter Mode
        /// </summary>
        CTR = 8,
        /// <summary>
        /// Output FeedBack Mode
        /// </summary>
        OFB = 16
    }
}
