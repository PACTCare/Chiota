#region Directives
using System.IO;
using NTRU.Sign;
using Test.Tests.Misc;
using System;
#endregion

namespace Test.Tests.Sign
{
    public class SignatureParametersTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";
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
        /// 
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                LoadSave();
                OnProgress(new TestEventArgs("Passed .."));
                EqualsHashCode();
                OnProgress(new TestEventArgs("Passed .."));
                CloneTest();
                OnProgress(new TestEventArgs("Passed .."));

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
        private void LoadSave()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD })
                LoadSave(param);
        }

        private void LoadSave(SignatureParameters param)
        {
            MemoryStream os = new MemoryStream();
            param.writeTo(os);
            MemoryStream ins = new MemoryStream(os.ToArray());
            Assert.Equals(param, new SignatureParameters(ins));
        }

        private void EqualsHashCode()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD })
                EqualsHashCode(param);
        }

        private void EqualsHashCode(SignatureParameters param)
        {
            MemoryStream os = new MemoryStream();
            param.writeTo(os);
            MemoryStream ins = new MemoryStream(os.ToArray());
            SignatureParameters params2 = new SignatureParameters(ins);

            Assert.Equals(param, params2);
            Assert.Equals(param.GetHashCode(), params2.GetHashCode());

            param.N += 1;
            Assert.False(param.Equals(params2));
            Assert.False(param.Equals(params2));
            Assert.False(param.GetHashCode() == params2.GetHashCode());
        }

        private void CloneTest()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD })
                Assert.Equals(param, param.Clone());
        }
        #endregion
    }
}