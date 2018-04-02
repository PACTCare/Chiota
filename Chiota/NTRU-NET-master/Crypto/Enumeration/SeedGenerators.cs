namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Seed Generators
    /// </summary>
    public enum SeedGenerators : int
    {
        /// <summary>
        /// A Secure Seed Generator using RNGCryptoServiceProvider
        /// </summary>
        CSPRsg,
        /// <summary>
        /// A Secure Seed Generator using an Xor+ generator
        /// </summary>
        XSPRsg
    }
}
