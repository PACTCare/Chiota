#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    /// LongPolynomial5 test
    /// </summary>
    public class LongPolynomial5Test : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the LongPolynomial5 implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! LongPolynomial5 tests have executed succesfully.";
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
        /// Test the validity of the LongPolynomial5 implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                MultTest();
                OnProgress(new TestEventArgs("Passed LongPolynomial5 multiply"));
                ToIntegerPolynomial();
                OnProgress(new TestEventArgs("Passed LongPolynomial5 ToIntegerPolynomial"));

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
        private void MultTest()
        {
            MultTest(new int[] { 2 }, new int[] { -1 });
            MultTest(new int[] { 2, 0 }, new int[] { -1, 0 });
            MultTest(new int[] { 2, 0, 3 }, new int[] { -1, 0, 1 });
            MultTest(new int[] { 2, 0, 3, 1 }, new int[] { -1, 0, 1, 1 });
            MultTest(new int[] { 2, 0, 3, 1, 2 }, new int[] { -1, 0, 1, 1, 0 });
            MultTest(new int[] { 2, 0, 3, 1, 1, 5 }, new int[] { 1, -1, 1, 1, 0, 1 });
            MultTest(new int[] { 2, 0, 3, 1, 1, 5, 1, 4 }, new int[] { 1, 0, 1, 1, -1, 1, 0, -1 });
            MultTest(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 }, new int[] { 1, 0, 1, 1, -1, 1, 0, -1 });

            // test random polynomials
            Random rng = new Random();
            for (int i = 0; i < 10; i++)
            {
                int[] coeffs1 = new int[rng.Next(2000) + 1];
                int[] coeffs2 = PolynomialGeneratorForTesting.generateRandom(coeffs1.Length).Coeffs;
                MultTest(coeffs1, coeffs2);
            }
        }

        private void ToIntegerPolynomial()
        {
            int[] coeffs = new int[] { 2, 0, 3, 1, 1, 5, 1, 4 };
            LongPolynomial5 p = new LongPolynomial5(new IntegerPolynomial(coeffs));

            if (!Compare.AreEqual(coeffs, p.ToIntegerPolynomial().Coeffs))
                throw new Exception("LongPolynomial5 multiply test failed!");
        }

        private void MultTest(int[] coeffs1, int[] coeffs2)
        {
            IntegerPolynomial i1 = new IntegerPolynomial(coeffs1);
            IntegerPolynomial i2 = new IntegerPolynomial(coeffs2);
            LongPolynomial5 a = new LongPolynomial5(i1);
            DenseTernaryPolynomial b = new DenseTernaryPolynomial(i2);
            IntegerPolynomial c1 = i1.Multiply(i2, 2048);
            IntegerPolynomial c2 = a.Multiply(b).ToIntegerPolynomial();

            if (!EqualsMod(c1.Coeffs, c2.Coeffs, 2048))
                throw new Exception("LongPolynomial5 multiply test failed!");
        }

        private bool EqualsMod(int[] arr1, int[] arr2, int m)
        {
            if (!Equals(arr1.Length, arr2.Length))
                return false;

            for (int i = 0; i < arr1.Length; i++)
            {
                if (!Equals((arr1[i] + m) % m, (arr2[i] + m) % m))
                    return false;
            }

            return true;
        }
        #endregion
    }
}