using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Cipher Padding Mode instance from it's enumeration name
    /// </summary>
    public static class PaddingFromName
    {
        /// <summary>
        /// Get a Padding Mode by name
        /// </summary>
        /// 
        /// <param name="PaddingType">The padding enumeration name</param>
        /// 
        /// <returns>An initialized padding mode</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static IPadding GetInstance(PaddingModes PaddingType)
        {
            switch (PaddingType)
            {
	            case PaddingModes.ISO7816:
		            return new ISO7816();
	            case PaddingModes.PKCS7:
		            return new PKCS7();
	            case PaddingModes.TBC:
		            return new TBC();
	            case PaddingModes.X923:
		            return new X923();
	            default:
                    throw new CryptoProcessingException("PaddingFromName:GetPadding", "The padding mode is not recognized!");
            }
        }
    }
}
