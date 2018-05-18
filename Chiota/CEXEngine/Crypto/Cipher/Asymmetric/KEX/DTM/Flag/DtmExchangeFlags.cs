namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// This enum represents the DTM KEX exchange state flags
    /// </summary>
    public enum DtmExchangeFlags : short
    {
        /// <summary>
        /// Public id fields exchange
        /// </summary>
        Connect = 1,
        /// <summary>
        /// Exchange full Public Identity
        /// </summary>
        Init = 2,
        /// <summary>
        /// Exchange Asymmetric Public keys
        /// </summary>
        PreAuth = 4,
        /// <summary>
        /// Exchange Symmetric KeyParams
        /// </summary>
        AuthEx = 8,
        /// <summary>
        /// Exchange Private Id's
        /// </summary>
        Auth = 16,
        /// <summary>
        /// Exchange Primary Asymmetric parameter OId's
        /// </summary>
        Sync = 32,
        /// <summary>
        /// Exchange Primary Public Keys
        /// </summary>
        PrimeEx = 64,
        /// <summary>
        /// Exchange Primary Symmetric keys
        /// </summary>
        Primary = 128,
        /// <summary>
        /// The VPN is established
        /// </summary>
        Established = 256,
        /// <summary>
        /// Negotiate the minimum security requirements
        /// </summary>
        Negotiate = 512
    }
}
