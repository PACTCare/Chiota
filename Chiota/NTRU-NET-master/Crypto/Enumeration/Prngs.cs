namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Pseudo Random Generators
    /// </summary>
    public enum Prngs : int
    {
        /// <summary>
        /// A Blum-Blum-Shub random number generator
        /// </summary>
        BBSG = 0,
        /// <summary>
        /// A Cubic Congruential Generator II (CCG) random number generator
        /// </summary>
        CCG,
        /// <summary>
        ///  A Secure PRNG using RNGCryptoServiceProvider
        /// </summary>
        CSPRng,
        /// <summary>
        /// A Symmetric Cipher Counter mode random number generator
        /// </summary>
        CTRPrng,
        /// <summary>
        /// A Digest Counter mode random number generator
        /// </summary>
        DGCPrng,
        /// <summary>
        /// A Modular Exponentiation Generator (MODEXPG) random number generator
        /// </summary>
        MODEXPG,
        /// <summary>
        /// An implementation of a passphrase based PKCS#5 random number generator
        /// </summary>
        PBPrng,
        /// <summary>
        /// A Quadratic Congruential Generator I (QCG-I) random number generator
        /// </summary>
        QCG1,
        /// <summary>
        /// A Quadratic Congruential Generator II (QCG-II) random number generator
        /// </summary>
        QCG2,
        /// <summary>
        /// An implementation of a Salsa20 Counter based Prng
        /// </summary>
        SP20Prng,
    }
}
