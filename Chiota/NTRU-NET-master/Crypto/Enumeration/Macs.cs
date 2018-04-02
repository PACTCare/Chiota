namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Message Authentication Code Generators
    /// </summary>
    public enum Macs : int
    {
        /// <summary>
        /// A Cipher based Message Authentication Code wrapper (CMAC)
        /// </summary>
        CMAC = 0,
        /// <summary>
        /// A Hash based Message Authentication Code wrapper (HMAC)
        /// </summary>
        HMAC,
        /// <summary>
        /// SHA256 Hash based Message Authentication Code
        /// </summary>
        SHA256HMAC,
        /// <summary>
        /// SHA512 Hash based Message Authentication Code
        /// </summary>
        SHA512HMAC,
        /// <summary>
        /// A Variably Modified Permutation Composition based Message Authentication Code (VMPC-MAC)
        /// </summary>
        VMPCMAC
    }
}
