using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Block Cipher instance from it's enumeration name
    /// </summary>
    public static class BlockCipherFromName
    {
        /// <summary>
        /// Get a block cipher instance with default initialization parameters.
        /// <para>The default parameters for each HX extended cipher, 128 bit block-size, Kdf as SHA2-256, and rounds equal to a 512 key setting</para>
        /// </summary>
        /// 
        /// <param name="BlockCipherType">The block cipher enumeration name</param>
        /// 
        /// <returns>An initialized block cipher</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static IBlockCipher GetInstance(BlockCiphers BlockCipherType)
        {
            switch (BlockCipherType)
            {
                case BlockCiphers.Rijndael:
                    return new RHX();
                case BlockCiphers.RHX:
                    return new RHX(16, 22, Digests.SHA256);
                case BlockCiphers.Serpent:
                    return new SHX();
                case BlockCiphers.SHX:
                    return new SHX(40, Digests.SHA256);
                case BlockCiphers.Twofish:
                    return new THX();
                case BlockCiphers.THX:
                    return new THX(20, Digests.SHA256);
                default:
                    throw new CryptoProcessingException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
            }
        }

        /// <summary>
        /// Get a block cipher instance with specified initialization parameters
        /// </summary>
        /// 
        /// <param name="BlockCipherType">The block cipher enumeration name</param>
        /// <param name="BlockSize">The cipher block size</param>
        /// <param name="RoundCount">The number of cipher rounds</param>
        /// <param name="ExtractorType">The ciphers key expansion engine</param>
        /// 
        /// <returns>An initialized block cipher</returns>
        public static IBlockCipher GetInstance(BlockCiphers BlockCipherType, int BlockSize, int RoundCount, Digests ExtractorType = Digests.None)
        {
            switch (BlockCipherType)
            {
                case BlockCiphers.Rijndael:
                    return new RHX(BlockSize);
                case BlockCiphers.RHX:
                    return new RHX(BlockSize, RoundCount, ExtractorType);
                case BlockCiphers.Serpent:
                    return new SHX();
                case BlockCiphers.SHX:
                    return new SHX(RoundCount, ExtractorType);
                case BlockCiphers.Twofish:
                    return new THX();
                case BlockCiphers.THX:
                    return new THX(RoundCount, ExtractorType);
                default:
                    throw new CryptoProcessingException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
            }
        }
    }
}
