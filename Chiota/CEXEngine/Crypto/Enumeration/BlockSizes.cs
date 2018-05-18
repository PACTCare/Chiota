namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// <para>Block cipher sizes in bits. Can be cast as Block byte size integers, 
    /// i.e. (int sz = BlockSizes.B512) is equal to 64.</para>
    /// </summary>
    public enum BlockSizes : int
    {
        /// <summary>
        /// 128 bit block size
        /// </summary>
        B128 = 16,
        /// <summary>
        /// 256 bit block size
        /// </summary>
        B256 = 32,
        /// <summary>
        /// 512 bit block size
        /// </summary>
        B512 = 64,
        /// <summary>
        /// 1024 bit block size
        /// </summary>
        B1024 = 128
    }
}
