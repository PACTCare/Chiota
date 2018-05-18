namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Binary key encoding schemes
    /// </summary>
    public enum EncodingSchemes : int
    {
        /// <summary>
        /// No encoding scheme was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// CER
        /// </summary>
        CER = 1,
        /// <summary>
        /// DER
        /// </summary>
        DER = 2,
        /// <summary>
        /// PEM
        /// </summary>
        PEM = 4
    }
}
