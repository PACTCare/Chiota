#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Polynomial
{
    /// <summary>
    /// SparseTernaryPolynomial test
    /// </summary>
    public class SparseTernaryPolynomialTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the SparseTernaryPolynomial implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! SparseTernaryPolynomial tests have executed succesfully.";
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
        /// Test the validity of the SparseTernaryPolynomial implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                MultTest();
                OnProgress(new TestEventArgs("Passed SparseTernaryPolynomial multiplication"));
                FromToBinary();
                OnProgress(new TestEventArgs("Passed SparseTernaryPolynomial FromToBinary"));
                GenerateRandom();
                OnProgress(new TestEventArgs("Passed SparseTernaryPolynomial GenerateRandom"));

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
        /** tests mult(IntegerPolynomial) and mult(BigIntPolynomial) */
        private void MultTest()
        {
            CSPRng rng = new CSPRng();
            SparseTernaryPolynomial p1 = SparseTernaryPolynomial.GenerateRandom(1000, 500, 500, rng);
            IntegerPolynomial p2 = PolynomialGeneratorForTesting.generateRandom(1000);

            IntegerPolynomial prod1 = p1.Multiply(p2);
            prod1 = p1.Multiply(p2);
            IntegerPolynomial prod2 = p1.Multiply(p2);

            if (!Compare.Equals(prod1, prod2))
                throw new Exception("SparseTernaryPolynomial multiplication test failed!");

            BigIntPolynomial p3 = new BigIntPolynomial(p2);
            BigIntPolynomial prod3 = p1.Multiply(p3);

            if (!Compare.Equals(new BigIntPolynomial(prod1), prod3))
                throw new Exception("SparseTernaryPolynomial multiplication test failed!");
        }

        private void FromToBinary()
        {
            CSPRng rng = new CSPRng();
            int N = 1000;
            SparseTernaryPolynomial poly1 = SparseTernaryPolynomial.GenerateRandom(N, 100, 101, rng);
            MemoryStream poly1Stream = new MemoryStream(poly1.ToBinary());
            SparseTernaryPolynomial poly2 = SparseTernaryPolynomial.FromBinary(poly1Stream, N);

            if (!Compare.Equals(poly1, poly2))
                throw new Exception("SparseTernaryPolynomial FromToBinary test failed!");
        }

        private void GenerateRandom()
        {
            CSPRng rng = new CSPRng();
            Verify(SparseTernaryPolynomial.GenerateRandom(743, 248, 248, rng));

            for (int i = 0; i < 10; i++)
            {
                int N = rng.Next(2000) + 10;
                int numOnes = rng.Next(N);
                int numNegOnes = rng.Next(N - numOnes);
                Verify(SparseTernaryPolynomial.GenerateRandom(N, numOnes, numNegOnes, rng));
            }
        }

        private void Verify(SparseTernaryPolynomial poly)
        {
            // make sure ones and negative ones don't share indices
            int[] ones = poly.GetOnes();
            int[] nones = poly.GetNegOnes();

            for (int i = 0; i < ones.Length; i++)
            {
                for (int j = 0; j < nones.Length; j++)
                {
                    if (ones[i] == nones[j])
                        throw new Exception("SparseTernaryPolynomial GenerateRandom test failed!");
                }
            }
        }
        #endregion
    }
}