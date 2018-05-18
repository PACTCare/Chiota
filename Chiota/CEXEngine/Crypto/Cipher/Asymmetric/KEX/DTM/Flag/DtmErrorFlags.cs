namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// The flag indicating the type of service request
    /// </summary>
    public enum DtmErrorFlags : short
    {
        /// <summary>
        /// Connection was dropped
        /// </summary>
        ConnectionDropped = 1,
        /// <summary>
        /// The client refused the connection
        /// </summary>
        ConnectionRefused = 2, 
        /// <summary>
        /// The connection terminated normally
        /// </summary>
        ConnectionTerminated = 4,
        /// <summary>
        /// The connection timed out
        /// </summary>
        ConnectionTimedOut = 8,
        /// <summary>
        /// The host had an unexpected error
        /// </summary>
        InternalError = 16,
        /// <summary>
        /// The maximum number of retransmission attempts for the session was exceeded
        /// </summary>
        MaxResendExceeded = 32,
        /// <summary>
        /// Unspecified network error
        /// </summary>
        NetworkError = 64,
        /// <summary>
        /// The session received bad data and can not recover
        /// </summary>
        ReceivedBadData = 128,
        /// <summary>
        /// Transmission could not be sent in a timely manner
        /// </summary>
        SendTimeoutExceeded = 256,
        /// <summary>
        /// Session encountered unrecoverable data loss
        /// </summary>
        UnrecoverableDataLoss = 512,
    }
}
