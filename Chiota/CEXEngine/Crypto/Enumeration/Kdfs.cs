namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Random Generator Digest KDFs
    /// </summary>
    public enum Kdfs : int
    {
        /// <summary>
        /// No kdf was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// A HMAC-based Key Derivation Function (HKDF)
        /// </summary>
        HKDF = 1,
        /// <summary>
        /// An implementation of the Key Derivation Function version 2 (KDF2)
        /// </summary>
        KDF2 = 2,
        /// <summary>
        /// An implementation of Passphrase Based Key Derivation Function version 2 (PBKDF2)
        /// </summary>
        PBKDF2 = 4
    }
}
