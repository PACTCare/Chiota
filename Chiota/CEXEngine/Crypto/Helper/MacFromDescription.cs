using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Mac generator instance from it's description
    /// </summary>
    public static class MacFromDescription
    {
        /// <summary>
        /// Get an uninitialized Mac generator from its description structure
        /// </summary>
        /// 
        /// <param name="Description">The structure describing the Mac generator</param>
        /// 
        /// <returns>An initialized Mac generator</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Mac type is not supported</exception>
        public static IMac GetInstance(MacDescription Description)
        {
            switch ((Macs)Description.MacType)
            {
                case Macs.CMAC:
                    {
                        return new CMAC((BlockCiphers)Description.EngineType);
                    }
                case Macs.HMAC:
                    {
                        return new HMAC((Digests)Description.HmacEngine);
                    }
                default:
                    throw new CryptoProcessingException("MacFromDescription:GetInstance", "The Mac generator is not recognized!");
            }
        }
    }
}
