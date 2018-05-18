#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Common
{
    /// <summary>
    /// An asymmetric cipher components helper class
    /// </summary>
    public static class AsymmetricUtils
    {
        /// <summary>
        /// Returns the cipher engine instance family type
        /// </summary>
        /// 
        /// <param name="Cipher">An instance of an asymmetric cipher</param>
        /// 
        /// <returns>The asymmetric family designator</returns>
        public static AsymmetricEngines GetCipherType(IAsymmetricCipher Cipher)
        {
            if (Cipher.GetType().Equals(typeof(NTRUEncrypt)))
                return AsymmetricEngines.NTRU;
            else if (Cipher.GetType().Equals(typeof(MPKCEncrypt)))
                return AsymmetricEngines.McEliece;
            else
                return AsymmetricEngines.RingLWE;
        }

        /// <summary>
        /// Returns the asymmetric keys family type
        /// </summary>
        /// 
        /// <param name="AsmKey">An asymmetric Public or Private key</param>
        /// 
        /// <returns>The asymmetric family designator</returns>
        public static AsymmetricEngines GetKeyType(IAsymmetricKey AsmKey)
        {
            if (AsmKey.GetType().Equals(typeof(NTRUPublicKey)) || AsmKey.GetType().Equals(typeof(NTRUPrivateKey)))
                return AsymmetricEngines.NTRU;
            else if (AsmKey.GetType().Equals(typeof(MPKCPublicKey)) || AsmKey.GetType().Equals(typeof(MPKCPrivateKey)))
                return AsymmetricEngines.McEliece;
            else if (AsmKey.GetType().Equals(typeof(RLWEPublicKey)) || AsmKey.GetType().Equals(typeof(RLWEPrivateKey)))
                return AsymmetricEngines.RingLWE;
            else if (AsmKey.GetType().Equals(typeof(RNBWPublicKey)) || AsmKey.GetType().Equals(typeof(RNBWPrivateKey)))
                return AsymmetricEngines.Rainbow;
            else
                return AsymmetricEngines.GMSS;
        }

        /// <summary>
        /// Returns the asymmetric parameters family type
        /// </summary>
        /// 
        /// <param name="Parameters">An asymmetric ciphers Parameters</param>
        /// 
        /// <returns>The asymmetric family designator</returns>
        public static AsymmetricEngines GetParametersType(IAsymmetricParameters Parameters)
        {
            if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                return AsymmetricEngines.NTRU;
            else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                return AsymmetricEngines.McEliece;
            else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                return AsymmetricEngines.RingLWE;
            else if (Parameters.GetType().Equals(typeof(RNBWParameters)))
                return AsymmetricEngines.Rainbow;
            else
                return AsymmetricEngines.GMSS;
        }

        /// <summary>
        /// Returns the signer engine instance family type
        /// </summary>
        /// 
        /// <param name="Signer">An instance of an asymmetric signer</param>
        /// 
        /// <returns>The asymmetric family designator</returns>
        public static AsymmetricEngines GetSignerType(IAsymmetricSign Signer)
        {
            if (Signer.GetType().Equals(typeof(MPKCSign)))
                return AsymmetricEngines.McEliece;
            else if (Signer.GetType().Equals(typeof(RLWESign)))
                return AsymmetricEngines.RingLWE;
            else if (Signer.GetType().Equals(typeof(RNBWSign)))
                return AsymmetricEngines.Rainbow;
            else
                return AsymmetricEngines.GMSS;
        }

        /// <summary>
        /// Test if the asymmetric key is a Public key
        /// </summary>
        /// 
        /// <param name="AsmKey">The asymmetric key</param>
        /// 
        /// <returns>Returns <c>true</c> if it is a Public key, <c>false</c> for a private key</returns>
        public static bool IsPublicKey(IAsymmetricKey AsmKey)
        {
            if (AsmKey.GetType().Equals(typeof(NTRUPublicKey)) || 
                AsmKey.GetType().Equals(typeof(MPKCPublicKey)) ||
                AsmKey.GetType().Equals(typeof(RLWEPublicKey)) ||
                AsmKey.GetType().Equals(typeof(RNBWPublicKey)) ||
                AsmKey.GetType().Equals(typeof(GMSSPublicKey)))
                return true;

            return false;
        }
    }
}
