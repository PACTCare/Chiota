namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Symmetric Encryption Ciphers
    /// </summary>
    public enum SymmetricEngines : int
    {
        /// <summary>
        /// No cipher was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
        /// </summary>
        RHX = 1,
        /// <summary>
        /// The Serpent Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        SHX = 2,
        /// <summary>
        /// A Twofish Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        THX = 4,
        /// <summary>
        /// An implementation of the ChaCha Stream Cipher
        /// </summary>
        ChaCha = 8,
        /// <summary>
        /// A Salsa20 Stream Cipher
        /// </summary>
        Salsa = 16
    }
}
