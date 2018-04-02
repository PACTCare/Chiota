#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    /// ProductFormPolynomial test
    /// </summary>
    public class ProductFormPolynomialTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the ProductFormPolynomial implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! ProductFormPolynomial tests have executed succesfully.";
        #endregion

        #region Fields
        private NTRUParameters _parameters;
        private int _N;
        private int _df1;
        private int _df2;
        private int _df3;
        private int _Q;
        private Random _rng;
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
        /// Test the validity of the ProductFormPolynomial implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                SetUp();
                FromToBinary();
                OnProgress(new TestEventArgs("Passed ProductFormPolynomial FromToBinary"));
                MultTest();
                OnProgress(new TestEventArgs("Passed ProductFormPolynomial multiplication"));

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
        private void SetUp()
        {
            _parameters = NTRUParamSets.APR2011439FAST;
            _N = _parameters.N;
            _df1 = _parameters.DF1;
            _df2 = _parameters.DF2;
            _df3 = _parameters.DF3;
            _Q = _parameters.Q;
            _rng = new Random();
        }

        private void FromToBinary()
        {
            CSPRng rng = new CSPRng();
            ProductFormPolynomial p1 = ProductFormPolynomial.GenerateRandom(_N, _df1, _df2, _df3, _df3 - 1, rng);
            byte[] bin1 = p1.ToBinary();
            ProductFormPolynomial p2 = ProductFormPolynomial.FromBinary(bin1, _N);

            if (!Compare.Equals(p1, p2))
                throw new Exception("ProductFormPolynomial FromToBinary test failed!");
        }

        private void MultTest()
        {
            CSPRng rng = new CSPRng();
            ProductFormPolynomial p1 = ProductFormPolynomial.GenerateRandom(_N, _df1, _df2, _df3, _df3 - 1, rng);
            IntegerPolynomial p2 = PolynomialGeneratorForTesting.GenerateRandom(_N, _Q);
            IntegerPolynomial p3 = p1.Multiply(p2);
            IntegerPolynomial p4 = p1.ToIntegerPolynomial().Multiply(p2);

            if (!Compare.Equals(p3, p4))
                throw new Exception("ProductFormPolynomial multiplication test failed!");
        }
        #endregion
    }
}