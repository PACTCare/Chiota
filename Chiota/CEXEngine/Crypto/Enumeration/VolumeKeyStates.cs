namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// The state of a volume key pair
    /// </summary>
    public enum VolumeKeyStates : byte
    {
        /// <summary>
        /// The key pair is unassigned
        /// </summary>
        Unassigned = 1,
        /// <summary>
        /// The key pair was used for encryption
        /// </summary>
        Encrypted = 2,
        /// <summary>
        /// The key pair was used for decryption
        /// </summary>
        Decrypted = 4
    }
}
