#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial
{
    /// <summary>
    /// Contains a resultant and a polynomial <c>rho</c> such that <c>res = rho*this + t*(x^n-1) for some integer t</c>.
    /// </summary>
    public class Resultant : IDisposable
    {
        #region Private Fields
        private bool _isDisposed = false;
        #endregion

        #region Public Fields
        /// <summary>
        /// A polynomial such that <c>res = rho*this + t*(x^n-1) for some integer t</c>
        /// </summary>
        public BigIntPolynomial Rho;
        /// <summary>
        /// Resultant of a polynomial with <c>x^n-1</c>
        /// </summary>
        public BigInteger Res;
        #endregion

        #region Constructor
        /// <summary>
        /// Stores the Rho and resultant values
        /// </summary>
        /// 
        /// <param name="Rho">A polynomial such that <c>res = rho*this + t*(x^n-1) for some integer t</c></param>
        /// <param name="Res">A polynomial with <c>x^n-1</c> </param>
        public Resultant(BigIntPolynomial Rho, BigInteger Res)
        {
            this.Rho = Rho;
            this.Res = Res;
        }

        ~Resultant()
        {
            Dispose(false);
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (Rho != null)
                        Rho.Clear();
                    if (Res != null)
                        Res = null;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}