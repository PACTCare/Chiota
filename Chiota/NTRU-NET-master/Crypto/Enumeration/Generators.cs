namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Random Generators
    /// </summary>
    public enum Generators : int
    {
        /// <summary>
        /// An implementation of a Encryption Counter based DRBG
        /// </summary>
        CTRDrbg = 0,
        /// <summary>
        /// An implementation of a Digest Counter based DRBG
        /// </summary>
        DGCDrbg,
        /// <summary>
        /// A Hash based Key Derivation Function HKDF
        /// </summary>
        HKDF,
        /// <summary>
        /// An implementation of a Hash based Key Derivation Function PBKDF2
        /// </summary>
        KDF2Drbg,
        /// <summary>
        /// An implementation of a Hash based Key Derivation PKCS#5 Version 2
        /// </summary>
        PKCS5,
        /// <summary>
        /// An implementation of a Salsa20 Counter based DRBG
        /// </summary>
        SP20Drbg,
    }
}
