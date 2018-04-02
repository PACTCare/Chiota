#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    /// DenseTernaryPolynomial test
    /// </summary>
    public class DenseTernaryPolynomialTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the DenseTernaryPolynomial implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! DenseTernaryPolynomial tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Test the validity of the DenseTernaryPolynomial implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                CheckTernarity(PolynomialGeneratorForTesting.generateRandom(1499));

                CSPRng rng = new CSPRng();
                for (int i = 0; i < 10; i++)
                {
                    int N = rng.Next(2000) + 10;
                    int numOnes = rng.Next(N);
                    int numNegOnes = rng.Next(N - numOnes);
                    CheckTernarity(DenseTernaryPolynomial.GenerateRandom(N, numOnes, numNegOnes, rng));
                }
                OnProgress(new TestEventArgs("Passed DenseTernaryPolynomial Ternarity"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private Methods
        private void CheckTernarity(DenseTernaryPolynomial poly)
        {
            if (!poly.IsTernary())
                throw new Exception("DenseTernaryPolynomial CheckTernarity test failed!");
        }
        #endregion
    }
}