#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic;
#endregion

namespace Test.Tests.Arith
{
    /// <summary>
    /// Test the validity of the IntEuclidean implementation
    /// </summary>
    public class IntEuclideanTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the IntEuclidean implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! IntEuclidean tests have executed succesfully.";
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
        /// IntEuclidean tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                IntEuclidean r = IntEuclidean.Calculate(120, 23);
                if (!r.X.Equals(-9))
                    throw new Exception("IntEuclidean failed r.X!");
                if (!r.Y.Equals(47))
                    throw new Exception("IntEuclidean failed r.Y!");
                if (!r.GCD.Equals(1))
                    throw new Exception("IntEuclidean failed r.GCD!");
                OnProgress(new TestEventArgs("Passed round 1 X, Y and GCD value comparisons"));

                r = IntEuclidean.Calculate(126, 231);
                if (!r.X.Equals(2))
                    throw new Exception("IntEuclidean failed r.X!");
                if (!r.Y.Equals(-1))
                    throw new Exception("IntEuclidean failed r.Y!");
                if (!r.GCD.Equals(21))
                    throw new Exception("IntEuclidean failed r.GCD!");
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