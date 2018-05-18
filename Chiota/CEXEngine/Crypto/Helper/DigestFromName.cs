using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Message Digest instance from it's enumeration name
    /// </summary>
    public static class DigestFromName
    {
        /// <summary>
        /// Get a Digest instance by name
        /// </summary>
        /// 
        /// <param name="DigestType">The message digest enumeration name</param>
        /// 
        /// <returns>An initialized digest</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static IDigest GetInstance(Digests DigestType, bool Parallel = false)
        {
	        switch (DigestType)
	        {
                case Digests.Blake2S256:
                    return new Blake2S256(Parallel);
                case Digests.Blake2B512:
                    return new Blake2B512(Parallel);
                case Digests.Keccak256:
		            return new Keccak256();
	            case Digests.Keccak512:
		            return new Keccak512();
	            case Digests.SHA256:
		            return new SHA256();
	            case Digests.SHA512:
		            return new SHA512();
	            case Digests.Skein256:
		            return new Skein256();
	            case Digests.Skein512:
		            return new Skein512();
	            case Digests.Skein1024:
		            return new Skein1024();
	            default:
                    throw new CryptoProcessingException("DigestFromName:GetInstance", "The digest is not recognized!");
	        }
        }

        /// <summary>
        /// Get the input block size of a message digest
        /// </summary>
        /// 
        /// <param name="DigestType">The Digest enumeration member</param>
        /// 
        /// <returns>The block size in bytes</returns>
        public static int GetBlockSize(Digests DigestType)
        {
            switch (DigestType)
            {
                case Digests.Skein256:
                    return 32;
                case Digests.Blake2S256:
                case Digests.SHA256:
                case Digests.Skein512:
                    return 64;
                case Digests.Blake2B512:
                case Digests.SHA512:
                case Digests.Skein1024:
                    return 128;
                case Digests.Keccak256:
                    return 136;
                case Digests.Keccak512:
                    return 72;
                case Digests.None:
                    return 0;
                default:
                    throw new CryptoSymmetricException("DigestFromName:GetBlockSize", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the hash size of a message digest
        /// </summary>
        /// 
        /// <param name="DigestType">The Digest enumeration member</param>
        /// 
        /// <returns>The hash size size in bytes</returns>
        public static int GetDigestSize(Digests DigestType)
        {
            switch (DigestType)
            {
                case Digests.Blake2S256:
                case Digests.Keccak256:
                case Digests.SHA256:
                case Digests.Skein256:
                    return 32;
                case Digests.Blake2B512:
                case Digests.Keccak512:
                case Digests.SHA512:
                case Digests.Skein512:
                    return 64;
                case Digests.Skein1024:
                    return 128;
                case Digests.None:
                    return 0;
                default:
                    throw new CryptoSymmetricException("DigestFromName:GetDigestSize", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the size of internal padding applied to the last block during the hash finalizer
        /// </summary>
        /// 
        /// <param name="DigestType">The Digest enumeration member</param>
        /// 
        /// <returns>The padding size size in bytes</returns>
        public static int GetPaddingSize(Digests DigestType)
        {
            switch (DigestType)
            {
                case Digests.Blake2B512:
                case Digests.Blake2S256:
                case Digests.Skein256:
                case Digests.Skein512:
                case Digests.Skein1024:
                    return 0;
                case Digests.Keccak256:
                case Digests.Keccak512:
                    return 1;
                case Digests.SHA256:
                    return 9;
                case Digests.SHA512:
                    return 17;
                case Digests.None:
                    return 0;
                default:
                    throw new CryptoSymmetricException("DigestFromName:GetDigestSize", "The digest type is not supported!", new ArgumentException());
            }
        }
    }
}
