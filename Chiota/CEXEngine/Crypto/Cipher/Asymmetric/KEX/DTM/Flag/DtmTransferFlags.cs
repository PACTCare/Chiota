namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// The flag indicating the state of a transfer operation
    /// </summary>
    public enum DtmTransferFlags : short
    {
        /// <summary>
        /// Packet contains a transfer request
        /// </summary>
        Request = 1,
        /// <summary>
        /// The transfer request was refused
        /// </summary>
        Refused = 2,
        /// <summary>
        /// Packet contains transmission data
        /// </summary>
        DataChunk = 4,
        /// <summary>
        /// The transfer receive operation has completed
        /// </summary>
        Received = 8,
        /// <summary>
        /// The transfer send operation has completed
        /// </summary>
        Sent = 16
    }
}
