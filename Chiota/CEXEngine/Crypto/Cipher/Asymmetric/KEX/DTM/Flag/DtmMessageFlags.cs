namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag
{
    /// <summary>
    /// The flag indicating the message payload type
    /// </summary>
    public enum DtmMessageFlags : short
    {
        /// <summary>
        /// The payload contains text based data
        /// </summary>
        Text = 1,
        /// <summary>
        /// The payload contains an audio stream
        /// </summary>
        Audio = 2,
        /// <summary>
        /// The payload contains a video stream
        /// </summary>
        Video = 4,
        /// <summary>
        /// The payload contains a public signing key
        /// </summary>
        Signing = 8,
        /// <summary>
        /// The payload contains an image file
        /// </summary>
        Image = 16
    }
}
