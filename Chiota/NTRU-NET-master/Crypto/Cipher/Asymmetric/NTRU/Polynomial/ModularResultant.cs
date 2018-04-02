#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Arithmetic;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// A resultant modulo a <c>BigInteger</c>
    /// </summary>
    public class ModularResultant : Resultant
    {
        #region Fields
        private BigInteger _modulus;
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiate the class
        /// </summary>
        /// 
        /// <param name="Rho">Rho code</param>
        /// <param name="Res">Resultant</param>
        /// <param name="Modulus">Modulus</param>
        public ModularResultant(BigIntPolynomial Rho, BigInteger Res, BigInteger Modulus) :
            base(Rho, Res)
        {
            this._modulus = Modulus;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Calculates a <c>rho</c> modulo <c>m1*m2</c> from two resultants whose 
        /// <c>rho</c>s are modulo <c>m1</c> and <c>m2</c>.
        /// <para><c>res</c> is set to <c>null</c>.</para>
        /// </summary>
        /// 
        /// <param name="ModRes1">M1 resultant</param>
        /// <param name="ModRes2">M2 resultant</param>
        /// 
        /// <returns><c>Rho</c> modulo <c>modRes1.modulus * modRes2.modulus</c>, and <c>null</c> for <c>res</c></returns>
        public static ModularResultant CombineRho(ModularResultant ModRes1, ModularResultant ModRes2)
        {
            BigInteger mod1 = ModRes1._modulus;
            BigInteger mod2 = ModRes2._modulus;
            BigInteger prod = mod1.Multiply(mod2);
            BigIntEuclidean er = BigIntEuclidean.Calculate(mod2, mod1);

            BigIntPolynomial rho1 = ModRes1.Rho.Clone();
            rho1.Multiply(er.X.Multiply(mod2));
            BigIntPolynomial rho2 = ModRes2.Rho.Clone();
            rho2.Multiply(er.Y.Multiply(mod1));
            rho1.Add(rho2);
            rho1.Mod(prod);

            return new ModularResultant(rho1, null, prod);
        }
        #endregion
    }
}