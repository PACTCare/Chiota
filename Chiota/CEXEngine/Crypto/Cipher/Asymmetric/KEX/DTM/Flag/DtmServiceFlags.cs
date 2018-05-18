namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// The flag indicating the type of service request
    /// </summary>
    public enum DtmServiceFlags : short
    {
        /// <summary>
        /// An internal error has occured
        /// </summary>
        Internal = 1,
        /// <summary>
        /// The host refused the connection
        /// </summary>
        Refusal = 2,
        /// <summary>
        /// The host was disconnected from the session
        /// </summary>
        Disconnected = 4,
        /// <summary>
        /// The host requires a re-transmission of the data
        /// </summary>
        Resend = 8,
        /// <summary>
        /// The host received data that was out of sequence
        /// </summary>
        OutOfSequence = 16,
        /// <summary>
        /// The data can not be recovered, attempt a resync
        /// </summary>
        DataLost = 32,
        /// <summary>
        /// Tear down the connection
        /// </summary>
        Terminate = 64,
        /// <summary>
        /// Response to a data lost messagem attempt to resync crypto stream
        /// </summary>
        Resync = 128,
        /// <summary>
        /// The response is an echo
        /// </summary>
        Echo = 256,
        /// <summary>
        /// The message is a keep alive
        /// </summary>
        KeepAlive = 512
    }
}
