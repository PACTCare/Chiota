namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support
{
    /// <summary>
    /// The flag sets the size of the Tcp/ip and internal buffers
    /// </summary>
    public enum DtmBufferSizes : int
    {
        /// <summary>
        /// Buffer size is calculated automatically
        /// </summary>
        Auto = 1,
        /// <summary>
        /// Buffer is 1 Kib in length (1024 bytes)
        /// </summary>
        KB1 = 1024,
        /// <summary>
        /// Buffer is 2 Kib in length (2048 bytes)
        /// </summary>
        KB2 = 2048,
        /// <summary>
        /// Buffer is 4 Kib in length (4096 bytes)
        /// </summary>
        KB4 = 4096,
        /// <summary>
        /// Buffer is 8 Kib in length (8192 bytes)
        /// </summary>
        KB8 = 8192,
        /// <summary>
        /// Buffer is 16 Kib in length (16384 bytes)
        /// </summary>
        KB16 = 16384,
        /// <summary>
        /// Buffer is 32 Kib in length (32768 bytes)
        /// </summary>
        KB32 = 32768,
        /// <summary>
        /// Buffer is 64 Kib in length (65536 bytes)
        /// </summary>
        KB64 = 65536,
        /// <summary>
        /// Buffer is 128 Kib in length (131072 bytes)
        /// </summary>
        KB128 = 131072,
        /// <summary>
        /// Buffer is 256 Kib in length (262144 bytes)
        /// </summary>
        KB256 = 262144,
        /// <summary>
        /// Buffer is 512 Kib in length (524288 bytes)
        /// </summary>
        KB512 = 524288,
        /// <summary>
        /// Buffer is 1024 Kib in length (1048576 bytes)
        /// </summary>
        KB1024 = 1048576,
    }
}
