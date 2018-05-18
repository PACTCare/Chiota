namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// Key Forwarding state flags used to describe the state of a key forwarding exchange
    /// </summary>
    public enum DtmForwardingFlags : short
    {
        /// <summary>
        /// The packet contains a forward key request message
        /// </summary>
        KeyRequest = 1,
        /// <summary>
        /// The packet contains a forward key response message
        /// </summary>
        KeyResponse = 2,
        /// <summary>
        /// Acknowledges the forward key has been received message
        /// </summary>
        KeyReturn = 4,
        /// <summary>
        /// The host has both keys message
        /// </summary>
        KeySynchronized = 8,
        /// <summary>
        /// The key request was refused message
        /// </summary>
        KeyRefused = 16,
        /// <summary>
        /// The packet contains a key forwarding message
        /// </summary>
        ForwardRequest = 32,
        /// <summary>
        /// The packet contains a key stream ratcheting message
        /// </summary>
        RatchetRequest = 64
    }
}
