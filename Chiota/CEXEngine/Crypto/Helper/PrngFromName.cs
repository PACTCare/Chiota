using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Prng instance from it's enumeration name
    /// </summary>
    public static class PrngFromName
    {
        /// <summary>
        /// Get a Prng instance with default initialization parameters
        /// </summary>
        /// 
        /// <param name="PrngType">The Prng enumeration name</param>
        /// 
        /// <returns>An initialized Prng</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static IRandom GetInstance(Prngs PrngType)
        {
            switch (PrngType)
            {
                case Prngs.CSPPrng:
                    return new CSPPrng();
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.SP20Prng:
                    return new SP20Prng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new CryptoProcessingException("PrngFromName:GetInstance", "The specified PRNG type is unrecognized!");
            }
        }
    }
}
