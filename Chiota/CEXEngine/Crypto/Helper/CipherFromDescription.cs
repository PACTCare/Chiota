using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a symmetric cipher instance from it's description
    /// </summary>
    public static class CipherFromDescription
    {
        /// <summary>
        /// Get an uninitialized symmetric cipher from its description structure
        /// </summary>
        /// 
        /// <param name="Description">The structure describing the symmetric cipher</param>
        /// 
        /// <returns>An uninitialized symmetric cipher</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Cipher type is not supported</exception>
        public static object GetInstance(CipherDescription Description)
        {
            switch ((SymmetricEngines)Description.EngineType)
            {
                case SymmetricEngines.RHX:
                case SymmetricEngines.SHX:
                case SymmetricEngines.THX:
                    {
                        return CipherModeFromName.GetInstance((CipherModes)Description.CipherType, BlockCipherFromName.GetInstance((BlockCiphers)Description.EngineType, Description.BlockSize, Description.RoundCount, (Digests)Description.KdfEngine));
                    }
                case SymmetricEngines.ChaCha:
                case SymmetricEngines.Salsa:
                    {
                        return StreamCipherFromName.GetInstance((StreamCiphers)Description.EngineType, Description.RoundCount);
                    }
                default:
                    throw new CryptoProcessingException("CipherFromDescription:GetInstance", "The symmetric cipher is not recognized!");
            }
        }
    }
}
