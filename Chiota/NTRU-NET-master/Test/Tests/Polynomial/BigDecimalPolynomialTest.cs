#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    ///  BigDecimalPolynomial test
    /// </summary>
    public class BigDecimalPolynomialTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the BigDecimalPolynomial implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! BigDecimalPolynomial tests have executed succesfully.";
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
        /// Test the validity of the BigDecimalPolynomial implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                BigDecimalPolynomial a = CreateBigDecimalPolynomial(new int[] { 4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5 });
                BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[] { -6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1 }));
                BigDecimalPolynomial c = a.Multiply(b);
                if(!Compare.AreEqual(c.Coeffs, CreateBigDecimalPolynomial(new int[] { 2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34 }).Coeffs))
                    throw new Exception("The BigDecimalPolynomial test failed!");
                // multiply a polynomial by its inverse modulo 2048 and check that the result is 1
                IntegerPolynomial d, dInv;
                CSPRng rng = new CSPRng();

                do
                {
                    d = DenseTernaryPolynomial.GenerateRandom(1001, 333, 334, rng);
                    dInv = d.InvertFq(2048);
                } while (dInv == null);

                d.Mod(2048);
                BigDecimalPolynomial e = CreateBigDecimalPolynomial(d.Coeffs);
                BigIntPolynomial f = new BigIntPolynomial(dInv);
                IntegerPolynomial g = new IntegerPolynomial(e.Multiply(f).Round());
                g.ModPositive(2048);

                if (!g.EqualsOne())
                    throw new Exception("The BigDecimalPolynomial test failed!");
                OnProgress(new TestEventArgs("Passed BigDecimalPolynomial tests"));

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
        private BigDecimalPolynomial CreateBigDecimalPolynomial(int[] coeffs)
        {
            int N = coeffs.Length;
            BigDecimalPolynomial poly = new BigDecimalPolynomial(N);

            for (int i = 0; i < N; i++)
                poly.Coeffs[i] = new BigDecimal(coeffs[i]);

            return poly;
        }
        #endregion
    }
}