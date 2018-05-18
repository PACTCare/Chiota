namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Random Generators
    /// </summary>
    public enum Drbgs : int
    {
        /// <summary>
        /// No generator was selected
        /// </summary>
        None = 0,
        /// <summary>
        /// An implementation of a encryption Counter Mode based pseudo random Generator (CMG)
        /// </summary>
        CMG = 1,
        /// <summary>
        /// An implementation of a Digest Counter based pseudo random Generator (DGC)
        /// </summary>
        DGC = 2,
        /// <summary>
        /// An implementation of a Salsa20 Based counter based pseudo random Generator (SBG)
        /// </summary>
        SBG = 4,
    }
}
