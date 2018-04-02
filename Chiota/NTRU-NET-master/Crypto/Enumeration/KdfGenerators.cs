namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Random Generator Digest KDFs
    /// </summary>
    public enum KdfGenerators : int
    {
        /// <summary>
        /// An implementation of a Digest Counter based DRBG
        /// </summary>
        DGCDRBG,
        /// <summary>
        /// A Hash based Key Derivation Function HKDF
        /// </summary>
        HKDF,
        /// <summary>
        /// An implementation of the Hash based KDF KDF2 DRBG
        /// </summary>
        KDF2,
        /// <summary>
        /// An implementation of PKCS5 Version 2
        /// </summary>
        PKCS5
    }
}
