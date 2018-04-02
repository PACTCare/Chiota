namespace VTDev.Libraries.CEXEngine.Crypto
{
    #region Enums
    /// <summary>
    /// Block Ciphers
    /// </summary>
    public enum BlockCiphers : int
    {
        /// <summary>
        /// An extended implementation of the Rijndael Block Cipher
        /// </summary>
        RDX,
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
        /// </summary>
        RHX,
        /// <summary>
        /// An implementation based on the Rijndael and Serpent Merged Block Cipher
        /// </summary>
        RSM,
        /// <summary>
        /// An extended implementation of the Serpent Block Cipher
        /// </summary>
        SPX,
        /// <summary>
        /// The Serpent Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        SHX,
        /// <summary>
        /// An extended implementation of the Twofish Block Cipher
        /// </summary>
        TFX,
        /// <summary>
        /// A Twofish Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        THX,
        /// <summary>
        /// An implementation based on the Twofish and Serpent Merged Block Ciphers, using an HKDF Key Schedule
        /// </summary>
        TSM
    }

    /// <summary>
    /// Message Digests
    /// </summary>
    public enum Digests : int
    {
        /// <summary>
        /// The Blake digest with a 256 bit return size
        /// </summary>
        Blake256 = 0,
        /// <summary>
        /// The Blake digest with a 512 bit return size
        /// </summary>
        Blake512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 512 bit return size
        /// </summary>
        Keccak256,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 256 bit return size
        /// </summary>
        Keccak512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 1024 bit return size
        /// </summary>
        Keccak1024,
        /// <summary>
        ///The SHA-2 digest with a 256 bit return size
        /// </summary>
        SHA256,
        /// <summary>
        /// The SHA-2 digest with a 512 bit return size
        /// </summary>
        SHA512,
        /// <summary>
        /// The Skein digest with a 256 bit return size
        /// </summary>
        Skein256,
        /// <summary>
        /// The Skein digest with a 512 bit return size
        /// </summary>
        Skein512,
        /// <summary>
        /// The Skein digest with a 1024 bit return size
        /// </summary>
        Skein1024
    }

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
        PKCS5
    }

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
        QCG2
    }

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
    #endregion
}