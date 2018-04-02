#region Direcives
using NTRU.Sign;
using System.IO;
using Test.Tests.Misc;
using System;
#endregion

namespace Test.Tests.Sign
{
    public class SignatureKeyTest : ITest
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
                foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD })
                    Encode(param);

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
        private void Encode(SignatureParameters param)
        {
            NtruSign ntru = new NtruSign(param);
            SignatureKeyPair kp = ntru.generateKeyPair();

            // encode to byte[] and reconstruct
            byte[] pub = kp.pub.getEncoded();
            byte[] priv = kp.priv.getEncoded();
            SignatureKeyPair kp2 = new SignatureKeyPair(new SignaturePrivateKey(priv), new SignaturePublicKey(pub));
            Assert.Equals(kp.pub, kp2.pub);
            Assert.Equals(kp.priv, kp2.priv);

            // encode to OutputStream and reconstruct
            MemoryStream bos1 = new MemoryStream();
            MemoryStream bos2 = new MemoryStream();
            kp.priv.writeTo(bos1);
            kp.pub.writeTo(bos2);
            MemoryStream bis1 = new MemoryStream(bos1.ToArray());
            MemoryStream bis2 = new MemoryStream(bos2.ToArray());
            SignatureKeyPair kp3 = new SignatureKeyPair(new SignaturePrivateKey(bis1), new SignaturePublicKey(bis2));
            Assert.Equals(kp.pub, kp3.pub);
            Assert.Equals(kp.priv, kp3.priv);
           // Assert.assertNull(kp3.priv.getBasis(0).h); ToDo: why?
        }
        #endregion
    }
}