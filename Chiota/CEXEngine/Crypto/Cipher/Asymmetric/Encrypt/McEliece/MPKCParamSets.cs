#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// Contains sets of predefined McEliece parameters.
    /// <para>Use the FromId(byte[]) or FromName(MPKCParamSets) to return a deep copy of a parameter set.</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <description>Parameter OId:</description>
    /// <list type="bullet">
    /// <item><description>A Parameter Set OId (uniquely identifies the parameter set), is always the first four bytes of a serialized parameter set.</description></item>
    /// <item><description>The OId format is ordered as: <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Unique</c>.</description></item>
    /// <item><description>A McEliece parameters Family designator (first byte) is always the value <c>1</c>, and corresponds to its entry in the <see cref="AsymmetricEngines"/> enumeration.</description></item>
    /// <item><description>The second byte (Set), defines the CCA2 Secure variant type, and corresponds to the <see cref="CCA2Ciphers"/> enumeration.</description></item>
    /// <item><description>The third byte indicates the M-base, 11, 12, 13, or 14.</description></item>
    /// <item><description>The fourth byte can be a unique designator.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: <a href="http://cacr.uwaterloo.ca/hac/about/chap8.pdf">Chapter 8</a></description></item>
    /// <item><description>Selecting Parameters for <a href="https://eprint.iacr.org/2010/271.pdf">Secure McEliece-based Cryptosystems</a></description></item>
    /// <item><description>Weak keys in the <a href="http://perso.univ-rennes1.fr/pierre.loidreau/articles/ieee-it/Cles_Faibles.pdf">McEliece Public-Key Crypto System</a></description></item>
    /// <item><description><a href="http://binary.cr.yp.to/mcbits-20130616.pdf">McBits</a>: fast constant-time code-based cryptography: </description></item>
    /// </list>
    /// </remarks>
    public static class MPKCParamSets
    {
        #region Enums
        /// <summary>
        /// Set id is defined as: Cipher(Fujisaki default), T value, M value, Digest family, Digest size 
        /// <para>FM11T40S256 = F(Fujisake): M11: T40: S(SHA-2): 256</para>
        /// </summary>
        public enum MPKCParamNames : int
        {
            /// <summary>
            /// Low security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:95, MaxText:201, K:1608 N:2048, PublicKey Size:88488, PrivateKey Size:119071, OId: 1, 1, 11, 1</para>
            /// </summary>
            FM11T40S256,
            /// <summary>
            /// Low security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:98, MaxText:190, K:1520 N:2048, PublicKey Size:100368, PrivateKey Size:142531, OId: 1, 1, 11, 2</para>
            /// </summary>
            FM11T48S256,
            /// <summary>
            /// Low to Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:108, MaxText:465, K:3724, N:4096, PublicKey Size: 175076, PrivateKey Size:200119, OId: 1, 1, 12, 1</para>
            /// </summary>
            FM12T31S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:129, MaxText:450, K:3604, N:4096, PublicKey Size: 223496, PrivateKey Size:262519, OId: 1, 1, 12, 2</para>
            /// </summary>
            FM12T41S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:131?, MaxText:440, K:3520, N:4096, PublicKey Size: 253488, PrivateKey Size:306371, OId: 1, 1, 12, 3</para>
            /// </summary>
            FM12T48S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and Keccak 256
            /// <para>Security:133?, MaxText:431, K:3448, N:4096, PublicKey Size: 306371, PrivateKey Size:344039, OId: 1, 1, 12, 4</para>
            /// </summary>
            FM12T54K256,
            /// <summary>
            /// High security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:148?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928, OId: 1, 1, 12, 5</para>
            /// </summary>
            FM12T67S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:128, MaxText:976, K:7815, N:8192, PublicKey Size: 375168, PrivateKey Size:403733, OId: 1, 1, 13, 1</para>
            /// </summary>
            FM13T29S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and Keccak 256
            /// <para>Security:136, MaxText:952, K:7620, N:8192, PublicKey Size: 548688, PrivateKey Size:604893, OId: 1, 1, 13, 2</para>
            /// </summary>
            FM13T44K256,
            /// <summary>
            /// High security; uses the Fujisaki cipher and SHA-256 (slow)
            /// <para>Security:190?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928, OId: 1, 1, 13, 3</para>
            /// </summary>
            FM13T95S256,
            /// <summary>
            /// Low to Medium security; uses the Fujisaki cipher and Keccak 256
            /// <para>Security:115, MaxText:2006, K:16048, N:16384, PublicKey Size: 674064, PrivateKey Size:721847, OId: 1, 1, 14, 1</para>
            /// </summary>
            FM14T24K256
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a parameter set by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 4 byte parameter set identity code</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static MPKCParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new CryptoAsymmetricException("MPKCParamSets:FromId", "OId can not be null!", new ArgumentException());
            if (OId.Length != 4)
                throw new CryptoAsymmetricException("MPKCParamSets:FromId", "OId must be 4 bytes in length!", new ArgumentException());
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParamSets:FromId", "OId is not a valid MPKC parameter id!", new ArgumentException());

            if (OId[2] == 11)
            {
                if (OId[3] == 1)
                    return (MPKCParameters)MPKCFM11T40S256.DeepCopy();
                else if (OId[3] == 2)
                    return (MPKCParameters)MPKCFM11T48S256.DeepCopy();
            }
            else if (OId[2] == 12)
            {
                if (OId[3] == 1)
                    return (MPKCParameters)MPKCFM12T31S256.DeepCopy();
                else if (OId[3] == 2)
                    return (MPKCParameters)MPKCFM12T41S256.DeepCopy();
                else if (OId[3] == 3)
                    return (MPKCParameters)MPKCFM12T48S256.DeepCopy();
                else if (OId[3] == 4)
                    return (MPKCParameters)MPKCFM12T54K256.DeepCopy();
                else if (OId[3] == 5)
                    return (MPKCParameters)MPKCFM12T67S256.DeepCopy();
            }
            else if (OId[2] == 13)
            {
                if (OId[3] == 1)
                    return (MPKCParameters)MPKCFM13T29S256.DeepCopy();
                else if (OId[3] == 2)
                    return (MPKCParameters)MPKCFM13T44K256.DeepCopy();
                else if (OId[3] == 3)
                    return (MPKCParameters)MPKCFM13T95S256.DeepCopy();
            }
            else if (OId[2] == 14)
            {
                if (OId[3] == 1)
                    return (MPKCParameters)MPKCFM14T24K256.DeepCopy();
            }

            throw new CryptoAsymmetricException("MPKCParamSets:FromId", "OId does not identify a valid param set!", new ArgumentException());
        }

        /// <summary>
        /// Retrieve a parameter set by its enumeration name
        /// </summary>
        /// 
        /// <param name="ParamName">The enumeration name</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static MPKCParameters FromName(MPKCParamNames ParamName)
        {
            switch (ParamName)
            {
                case MPKCParamNames.FM11T40S256:
                    return (MPKCParameters)MPKCFM11T40S256.DeepCopy();
                case MPKCParamNames.FM11T48S256:
                    return (MPKCParameters)MPKCFM11T48S256.DeepCopy();
                case MPKCParamNames.FM12T31S256:
                    return (MPKCParameters)MPKCFM12T31S256.DeepCopy();
                case MPKCParamNames.FM12T41S256:
                    return (MPKCParameters)MPKCFM12T41S256.DeepCopy();
                case MPKCParamNames.FM12T48S256:
                    return (MPKCParameters)MPKCFM12T48S256.DeepCopy();
                case MPKCParamNames.FM12T54K256:
                    return (MPKCParameters)MPKCFM12T54K256.DeepCopy();
                case MPKCParamNames.FM12T67S256:
                    return (MPKCParameters)MPKCFM12T67S256.DeepCopy();
                case MPKCParamNames.FM13T29S256:
                    return (MPKCParameters)MPKCFM13T29S256.DeepCopy();
                case MPKCParamNames.FM13T44K256:
                    return (MPKCParameters)MPKCFM13T44K256.DeepCopy();
                case MPKCParamNames.FM13T95S256:
                    return (MPKCParameters)MPKCFM13T95S256.DeepCopy();
                case MPKCParamNames.FM14T24K256:
                    return (MPKCParameters)MPKCFM14T24K256.DeepCopy();
                default:
                    throw new CryptoAsymmetricException("MPKCParamSets:FromName", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get a serialized MPKCParameters class from a parameter name
        /// </summary>
        /// 
        /// <param name="ParamName">The McEliece Parameters set name</param>
        /// 
        /// <returns>The serialized MPKCParameters set</returns>
        public static byte[] GetFormatted(MPKCParamNames ParamName)
        {
            return FromName(ParamName).ToBytes();
        }

        /// <summary>
        /// Retrieve the parameter OId by its enumeration name
        /// </summary>
        /// 
        /// <param name="ParamName">The enumeration name</param>
        /// 
        /// <returns>The 4 byte OId field</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static byte[] GetID(MPKCParamNames ParamName)
        {
            switch (ParamName)
            {
                case MPKCParamNames.FM11T40S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 11, 1 };
                case MPKCParamNames.FM11T48S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 11, 2 };
                case MPKCParamNames.FM12T31S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 1 };
                case MPKCParamNames.FM12T41S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 2 };
                case MPKCParamNames.FM12T48S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 3 };
                case MPKCParamNames.FM12T54K256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 4 };
                case MPKCParamNames.FM12T67S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 5 };
                case MPKCParamNames.FM13T29S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 13, 1 };
                case MPKCParamNames.FM13T44K256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 13, 2 };
                case MPKCParamNames.FM13T95S256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 13, 3 };
                case MPKCParamNames.FM14T24K256:
                    return new byte[] { (byte)AsymmetricEngines.McEliece, 1, 14, 1 };
                default:
                    throw new CryptoAsymmetricException("MPKCParamSets:GetID", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }
        #endregion

        #region Parameter Sets
        // Note: Oid = family, mbase, ordinal
        /// <summary>
        /// Low security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:95, MaxText:201, K:1608 N:2048, PublicKey Size:88488, PrivateKey Size:119071, OId: 1, 1, 11, 1</para>
        /// </summary>
        public static MPKCParameters MPKCFM11T40S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 11, 1 }, 11, 40, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:98, MaxText:190, K:1520 N:2048, PublicKey Size:100368, PrivateKey Size:142531, OId: 1, 1, 11, 2</para>
        /// </summary>
        public static MPKCParameters MPKCFM11T48S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 11, 2 }, 11, 48, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low to Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:108, MaxText:465, K:3724, N:4096, PublicKey Size: 175076, PrivateKey Size:200119, OId: 1, 1, 12, 1</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T31S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 1 }, 12, 31, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:129, MaxText:450, K:3604, N:4096, PublicKey Size: 223496, PrivateKey Size:262519, OId: 1, 1, 12, 2</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T41S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 2 }, 12, 41, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:131?, MaxText:440, K:3520, N:4096, PublicKey Size: 253488, PrivateKey Size:306371, OId: 1, 1, 12, 3</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T48S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 3 }, 12, 48, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:133?, MaxText:431, K:3448, N:4096, PublicKey Size: 306371, PrivateKey Size:344039, OId: 1, 1, 12, 4</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T54K256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 4 }, 12, 54, CCA2Ciphers.Fujisaki, Digests.Keccak256);

        /// <summary>
        /// High security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:148?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928, OId: 1, 1, 12, 5</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T67S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 12, 5 }, 12, 67, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:128, MaxText:976, K:7815, N:8192, PublicKey Size: 375168, PrivateKey Size:403733, OId: 1, 1, 13, 1</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T29S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 13, 1 }, 13, 29, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:136, MaxText:952, K:7620, N:8192, PublicKey Size: 548688, PrivateKey Size:604893, OId: 1, 1, 13, 2</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T44K256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 13, 2 }, 13, 44, CCA2Ciphers.Fujisaki, Digests.Keccak256);

        /// <summary>
        /// High security; uses the Fujisaki cipher and SHA-256 (slow)
        /// <para>Security:190?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928, OId: 1, 1, 13, 3</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T95S256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 13, 3 }, 13, 95, CCA2Ciphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low to Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:115, MaxText:2006, K:16048, N:16384, PublicKey Size: 674064, PrivateKey Size:721847, OId: 1, 1, 14, 1</para>
        /// </summary>
        public static MPKCParameters MPKCFM14T24K256 = new MPKCParameters(new byte[] { (byte)AsymmetricEngines.McEliece, 1, 14, 1 }, 14, 24, CCA2Ciphers.Fujisaki, Digests.Keccak256);
        #endregion
    }
}
