#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    /// BigIntPolynomial test
    /// </summary>
    public class BigIntPolynomialTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the BigIntPolynomial implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! BigIntPolynomial tests have executed succesfully.";
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
        /// Test the validity of the BigIntPolynomial implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                BigIntPolynomial a = new BigIntPolynomial(new IntegerPolynomial(new int[] { 4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5 }));
                BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[] { -6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1 }));
                BigIntPolynomial expected = new BigIntPolynomial(new IntegerPolynomial(new int[] { 2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34 }));
                if (!Compare.AreEqual(expected.Coeffs, a.MultSmall(b).Coeffs))
                    throw new Exception("BigIntPolynomial known value test failed!");
                OnProgress(new TestEventArgs("Passed round 1 BigIntPolynomial known value"));

                if (!Compare.AreEqual(expected.Coeffs, a.MultBig(b).Coeffs))
                    throw new Exception("BigIntPolynomial known value test failed!");
                OnProgress(new TestEventArgs("Passed round 2 BigIntPolynomial known value"));

                Random rng = new Random();
                BigInteger[] aCoeffs = new BigInteger[10 + rng.Next(50)];
                BigInteger[] bCoeffs = new BigInteger[aCoeffs.Length];

                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < aCoeffs.Length; j++)
                    {
                        byte[] aArr = new byte[600 + rng.Next(100)];
                        rng.NextBytes(aArr);
                        aCoeffs[j] = new BigInteger(aArr);
                        byte[] bArr = new byte[600 + rng.Next(100)];
                        rng.NextBytes(bArr);
                        bCoeffs[j] = new BigInteger(bArr);
                    }
                    a = new BigIntPolynomial(aCoeffs);
                    b = new BigIntPolynomial(bCoeffs);
                    if (!Compare.AreEqual(a.MultSmall(b).Coeffs, a.MultBig(b).Coeffs))
                        throw new Exception("BigIntPolynomial coefficient comparison test failed!");
                }
                OnProgress(new TestEventArgs("Passed BigIntPolynomial coefficient comparison"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion
    }
}