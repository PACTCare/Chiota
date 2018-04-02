#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

namespace Test.Tests.Arith
{
    /// <summary>
    /// Test the validity of the BigIntEuclidean implementation
    /// </summary>
    public class BigIntEuclideanTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the BigIntEuclidean implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! BigIntEuclidean tests have executed succesfully.";
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
        /// BigIntEuclidean tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                BigIntEuclidean r = BigIntEuclidean.Calculate(BigInteger.ValueOf(120), BigInteger.ValueOf(23));
                if (!BigInteger.ValueOf(-9).Equals(r.X))
                    throw new Exception("BigIntEuclidean failed r.X!");
                if (!BigInteger.ValueOf(47).Equals(r.Y))
                    throw new Exception("BigIntEuclidean failed r.Y!");
                if (!BigInteger.ValueOf(1).Equals(r.GCD))
                    throw new Exception("BigIntEuclidean failed r.GCD!");
                OnProgress(new TestEventArgs("Passed round 1 X, Y and GCD value comparisons"));

                r = BigIntEuclidean.Calculate(BigInteger.ValueOf(126), BigInteger.ValueOf(231));
                if (!BigInteger.ValueOf(2).Equals(r.X))
                    throw new Exception("BigIntEuclidean failed r.X!");
                if (!BigInteger.ValueOf(-1).Equals(r.Y))
                    throw new Exception("BigIntEuclidean failed r.Y!");
                if (!BigInteger.ValueOf(21).Equals(r.GCD))
                    throw new Exception("BigIntEuclidean failed r.GCD!");
                OnProgress(new TestEventArgs("Passed round 2 X, Y and GCD value comparisons"));

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