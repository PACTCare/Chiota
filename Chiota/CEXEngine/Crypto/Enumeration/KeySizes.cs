namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// <para>Key Sizes in bits. Can be cast as Key byte size integers, 
    /// i.e. (uint sz = KeySizes.K256) is equal to 32.</para>
    /// </summary>
    public enum KeySizes : int
    {
        /// <summary>
        /// 128 bit Key
        /// </summary>
        K128 = 16,
        /// <summary>
        /// 192 bit Key
        /// </summary>
        K192 = 24,
        /// <summary>
        /// 256 bit Key
        /// </summary>
        K256 = 32,
        /// <summary>
        /// 512 bit Key
        /// </summary>
        K512 = 64,
        /// <summary>
        /// 768 bit Key
        /// </summary>
        K768 = 96,
        /// <summary>
        /// 1024 bit Key
        /// </summary>
        K1024 = 128,
        /// <summary>
        /// 1280 bit Key
        /// </summary>
        K1280 = 160,
        /// <summary>
        /// 1536 bit Key
        /// </summary>
        K1536 = 192,
        /// <summary>
        /// 1792 bit Key
        /// </summary>
        K1792 = 224,
        /// <summary>
        /// 2048 bit Key
        /// </summary>
        K2048 = 256,
        /// <summary>
        /// 2304 bit Key
        /// </summary>
        K2304 = 288,
        /// <summary>
        /// 2560 bit Key
        /// </summary>
        K2560 = 320,
    }
}
