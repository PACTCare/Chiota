#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// Core operations for the CCA-secure variants of McEliece
    /// </summary>
    internal sealed class CCA2Primitives
    {
        #region Constructor
        private CCA2Primitives()
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// The McEliece encryption primitive
        /// </summary>
        /// 
        /// <param name="PublicKey">The public key</param>
        /// <param name="M">The message vector</param>
        /// <param name="Z">The error vector</param>
        /// 
        /// <returns><c>m*G + z</c></returns>
        public static GF2Vector Encrypt(MPKCPublicKey PublicKey, GF2Vector M, GF2Vector Z)
        {
            GF2Matrix matrixG = PublicKey.G;
            Vector mG = matrixG.LeftMultiplyLeftCompactForm(M);

            return (GF2Vector)mG.Add(Z);
        }

        /// <summary>
        /// The McEliece decryption primitive
        /// </summary>
        /// 
        /// <param name="PrivateKey">The private key</param>
        /// <param name="C">The ciphertext vector <c>c = m*G + z</c></param>
        /// 
        /// <returns>The message vector <c>m</c> and the error vector <c>z</c></returns>
        public static GF2Vector[] Decrypt(MPKCPrivateKey PrivateKey, GF2Vector C)
        {
            // obtain values from private key
            int k = PrivateKey.K;
            Permutation p = PrivateKey.P1;
            GF2mField field = PrivateKey.GF;
            PolynomialGF2mSmallM gp = PrivateKey.GP;
            GF2Matrix h = PrivateKey.H;
            PolynomialGF2mSmallM[] q = PrivateKey.QInv;

            // compute inverse permutation P^-1
            Permutation pInv = p.ComputeInverse();
            // multiply c with permutation P^-1
            GF2Vector cPInv = (GF2Vector)C.Multiply(pInv);
            // compute syndrome of cP^-1
            GF2Vector syndVec = (GF2Vector)h.RightMultiply(cPInv);
            // decode syndrome
            GF2Vector errors = GoppaCode.SyndromeDecode(syndVec, field, gp, q);
            GF2Vector mG = (GF2Vector)cPInv.Add(errors);
            // multiply codeword and error vector with P
            mG = (GF2Vector)mG.Multiply(p);
            errors = (GF2Vector)errors.Multiply(p);
            // extract plaintext vector (last k columns of mG)
            GF2Vector m = mG.ExtractRightVector(k);

            // return vectors
            return new GF2Vector[] { m, errors };
        }
        #endregion
    }
}
