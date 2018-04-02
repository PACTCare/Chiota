namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
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
}
