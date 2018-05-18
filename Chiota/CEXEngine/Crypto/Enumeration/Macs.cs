namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Message Authentication Code Generators
    /// </summary>
    public enum Macs : int
    {
        /// <summary>
        /// No mac was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// A Cipher based Message Authentication Code wrapper (CMAC)
        /// </summary>
        CMAC = 1,
        /// <summary>
        /// A Hash based Message Authentication Code wrapper (HMAC)
        /// </summary>
        HMAC = 2
    }
}
