namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Asymmetric Encryption Ciphers
    /// </summary>
    public enum AsymmetricEngines : int
    {
        /// <summary>
        /// An McEliece CCA2 cipher implementation
        /// </summary>
        McEliece = 1,
        /// <summary>
        /// An NTRU cipher implementation
        /// </summary>
        NTRU = 2,
        /// <summary>
        /// An Ring-LWE cipher implementation
        /// </summary>
        RingLWE = 3
    }
}
