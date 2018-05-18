using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Prng instance from it's enumeration name
    /// </summary>
    public static class SeedGeneratorFromName
    {
        /// <summary>
        /// Get a Seed Generator instance with default initialization parameters
        /// </summary>
        /// 
        /// <param name="SeedType">The prng enumeration name</param>
        /// 
        /// <returns>An initialized Seed Generator</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static ISeed GetInstance(SeedGenerators SeedType)
        {
            switch (SeedType)
            {
                case SeedGenerators.CSPRsg:
                    return new CSPRsg();
                case SeedGenerators.CTRRsg:
                    return new CTRRsg();
                case SeedGenerators.ISCRsg:
                    return new ISCRsg();
                case SeedGenerators.SP20Rsg:
                    return new SP20Rsg();
                default:
                    throw new CryptoProcessingException("SeedGeneratorFromName:GetInstance", "The specified generator type is unrecognized!");
            }
        }
    }
}
