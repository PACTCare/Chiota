namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Asymmetric Encryption Ciphers
    /// </summary>
    public enum AsymmetricEngines : int
    {
        /// <summary>
        /// No cipher was selected
        /// </summary>
        None = 0,
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
        RingLWE = 3,
        /// <summary>
        /// A Rainbow signing implementation
        /// </summary>
        Rainbow = 4,
        /// <summary>
        /// A Generalized Merkle Signature Scheme implementation
        /// </summary>
        GMSS = 5
    }
}
