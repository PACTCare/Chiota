#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    /// LongPolynomial2 test
    /// </summary>
    public class LongPolynomial2Test : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the LongPolynomial2 implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! LongPolynomial2 tests have executed succesfully.";
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
        /// Test the validity of the LongPolynomial2 implementation"
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                MultTest();
                OnProgress(new TestEventArgs("Passed LongPolynomial2 multiplication"));
                SubAndTest();
                OnProgress(new TestEventArgs("Passed LongPolynomial2 SubAnd"));
                Mult2AndTest();
                OnProgress(new TestEventArgs("Passed LongPolynomial2 Mult2And"));

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
            IntegerPolynomial i1 = new IntegerPolynomial(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 });
            IntegerPolynomial i2 = new IntegerPolynomial(new int[] { 1729, 1924, 806, 179, 1530, 1381, 1695, 60 });
            LongPolynomial2 a = new LongPolynomial2(i1);
            LongPolynomial2 b = new LongPolynomial2(i2);
            IntegerPolynomial c1 = i1.Multiply(i2, 2048);
            IntegerPolynomial c2 = a.Multiply(b).ToIntegerPolynomial();

            if (!Compare.AreEqual(c1.Coeffs, c2.Coeffs))
                throw new Exception("LongPolynomial2 multiply test failed!");

            // test 10 random polynomials
            Random rng = new Random();
            for (int i = 0; i < 10; i++)
            {
                int N = 2 + rng.Next(2000);
                i1 = (IntegerPolynomial)PolynomialGeneratorForTesting.GenerateRandom(N, 2048);
                i2 = (IntegerPolynomial)PolynomialGeneratorForTesting.GenerateRandom(N, 2048);
                a = new LongPolynomial2(i1);
                b = new LongPolynomial2(i2);
                c1 = i1.Multiply(i2);
                c1.ModPositive(2048);
                c2 = a.Multiply(b).ToIntegerPolynomial();

                if (!Compare.AreEqual(c1.Coeffs, c2.Coeffs))
                    throw new Exception("LongPolynomial2 multiply test failed!");
            }
        }

        private void SubAndTest()
        {
            IntegerPolynomial i1 = new IntegerPolynomial(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 });
            IntegerPolynomial i2 = new IntegerPolynomial(new int[] { 1729, 1924, 806, 179, 1530, 1381, 1695, 60 });
            LongPolynomial2 a = new LongPolynomial2(i1);
            LongPolynomial2 b = new LongPolynomial2(i2);
            a.SubAnd(b, 2047);
            i1.Subtract(i2);
            i1.ModPositive(2048);

            if (!Compare.AreEqual(a.ToIntegerPolynomial().Coeffs, i1.Coeffs))
                throw new Exception("LongPolynomial2 SubAnd test failed!");
        }

        private void Mult2AndTest()
        {
            IntegerPolynomial i1 = new IntegerPolynomial(new int[] { 1368, 2047, 672, 871, 1662, 1352, 1099, 1608 });
            LongPolynomial2 i2 = new LongPolynomial2(i1);
            i2.Mult2And(2047);
            i1.Multiply(2);
            i1.ModPositive(2048);

            if (!Compare.AreEqual(i1.Coeffs, i2.ToIntegerPolynomial().Coeffs))
                throw new Exception("LongPolynomial2 Mult2And test failed!");
        }
        #endregion
    }
}