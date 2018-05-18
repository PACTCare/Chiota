namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// The McEliece CCA2 Secure ciphers
    /// </summary>
    public enum CCA2Ciphers : int
    {
        /// <summary>
        /// The Fujisaki/Okamoto conversion of the McEliece PKCS
        /// </summary>
        Fujisaki = 1,
        /// <summary>
        /// The Kobara/Imai conversion of the McEliece PKCS
        /// </summary>
        KobaraImai = 2,
        /// <summary>
        /// The Pointcheval conversion of the McEliece PKCS
        /// </summary>
        Pointcheval = 3,
    }
}
