using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Cipher Mode instance from it's enumeration name
    /// </summary>
    public static class CipherModeFromName
    {
        /// <summary>
        /// Get an Cipher Mode instance by name using default parameters
        /// </summary>
        /// 
        /// <param name="CipherType">The cipher mode enumeration name</param>
        /// <param name="Engine">The block cipher instance</param>
        /// 
        /// <returns>An initialized digest</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static ICipherMode GetInstance(CipherModes CipherType, IBlockCipher Engine)
        {
            switch (CipherType)
	        {
	            case CipherModes.CTR:
		            return new CTR(Engine);
	            case CipherModes.CBC:
		            return new CBC(Engine);
	            case CipherModes.CFB:
		            return new CFB(Engine);
	            case CipherModes.OFB:
		            return new OFB(Engine);
	            default:
                    throw new CryptoProcessingException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
	        }
        }
    }
}
