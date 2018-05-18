using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Stream Cipher instance from it's enumeration name
    /// </summary>
    public static class StreamCipherFromName
    {
        /// <summary>
        /// Get a stream cipher instance with specified initialization parameters
        /// </summary>
        /// 
        /// <param name="StreamCipherType">The stream cipher enumeration name</param>
        /// <param name="RoundCount">The number of cipher rounds</param>
        /// 
        /// <returns>An initialized stream cipher</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static IStreamCipher GetInstance(StreamCiphers StreamCipherType, int RoundCount = 20)
        {
            switch (StreamCipherType)
            {
                case StreamCiphers.ChaCha:
                    return new ChaCha20(RoundCount);
                case StreamCiphers.Salsa:
                    return new Salsa20(RoundCount);
                default:
                    throw new CryptoProcessingException("StreamCipherFromName:GetStreamEngine", "The stream cipher is not recognized!");
            }
        }
    }
}
