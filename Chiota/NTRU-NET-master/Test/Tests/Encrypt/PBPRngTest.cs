#region Directives
using System;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Encrypt
{
    /// <summary>
    /// Test the validity of the Passphrase based random generator implementation
    /// </summary>
    public class PBPRngTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the PBPRng implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! PBPRng tests have executed succesfully.";
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
        /// PBPRng test
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                NextTest();
                OnProgress(new TestEventArgs("Passed get next random threshhold tests"));
                CreateBranch();
                OnProgress(new TestEventArgs("Passed branch comparison tests"));

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
        private void NextTest()
        {
            PBPRng rng = CreateRng();

            if (!Compare.True(rng.Next(1) < 2))
                throw new Exception("PBPRng: next random test failed!");
            if (!Compare.True(rng.Next(1) >= 0))
                throw new Exception("PBPRng: next random test failed!");
            if (!Compare.True(rng.Next(8) < 256))
                throw new Exception("PBPRng: next random test failed!");
            if (!Compare.True(rng.Next(8) >= 0))
                throw new Exception("PBPRng: next random test failed!");
            if (!Compare.True(rng.Next(11) < 2048))
                throw new Exception("PBPRng: next random test failed!");
            if (!Compare.True(rng.Next(11) >= 0))
                throw new Exception("PBPRng: next random test failed!");
            if (!Compare.True(rng.Next(31) >= 0))
                throw new Exception("PBPRng: next random test failed!");
        }

        private void CreateBranch()
        {
            PBPRng rng1 = CreateRng();
            PBPRng rng2 = rng1.CreateBranch(new SHA512());

            byte[] data1 = new byte[32];
            rng2.GetBytes(data1);

            rng1 = CreateRng();
            rng2 = rng1.CreateBranch(new SHA512());
            byte[] data2 = new byte[32];
            rng2.GetBytes(data2);
            // should be equal
            if (!Compare.AreEqual(data1, data2))
                throw new Exception("PBPRng: create branch test failed!");
        }

        private PBPRng CreateRng()
        {
            return new PBPRng(new SHA512(), Encoding.Unicode.GetBytes("my secret passphrase"), ByteUtils.ToBytes(new sbyte[] { -37, 103, 50, -91, 2, -43, -106, 65 }));
        }
        #endregion
    }
}