namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Seed Generators
    /// </summary>
    public enum SeedGenerators : int
    {
        /// <summary>
        /// No seed generator was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// A Secure Seed Generator using an AES256 CTR generator
        /// </summary>
        CTRRsg = 1,
        /// <summary>
        /// A Secure Seed Generator using the RNGCryptoServiceProvider api
        /// </summary>
        CSPRsg = 2,
        /// <summary>
        /// A Secure Seed Generator using the ISAAC generator
        /// </summary>
        ISCRsg = 4,
        /// <summary>
        /// A Secure Seed Generator using SalsaP20 generator
        /// </summary>
        SP20Rsg = 8
    }
}
