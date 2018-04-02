#region Directives
using System.IO;
using NTRU.Arith;
using NTRU.Polynomial;
using NTRU.Sign;
using Test.Tests.Misc;
using System;
#endregion

namespace Test.Tests.Sign
{
    public class SignatureKeyPairTest : ITest
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
                IsValid();
                OnProgress(new TestEventArgs("Passed .."));
                Encode();
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
        private void IsValid()
        {
            // test valid key pairs
            NtruSign ntru = null;
            SignatureKeyPair kp = null;
            SignatureParameters[] paramSets = new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD };
            foreach (SignatureParameters param in paramSets)
            {
                ntru = new NtruSign(param);
                kp = ntru.generateKeyPair();
                Assert.True(kp.isValid());
            }

            // test an invalid key pair
            int q = kp.pub.q;
            kp.pub.h.Multiply(101);   // make h invalid
            kp.pub.h.ModPositive(q);
            Assert.False(kp.isValid());
            int inv101 = IntEuclidean.Calculate(101, q).X;
            kp.pub.h.Multiply(inv101);   // restore h
            kp.pub.h.ModPositive(q);
            IntegerPolynomial f = kp.priv.getBasis(0).f.ToIntegerPolynomial();
            f.Multiply(3);   // make f invalid
            kp.priv.getBasis(0).f = f;
            Assert.False(kp.isValid());
        }

        private void Encode()
        {
            SignatureParameters[] paramSets = new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD };
            foreach (SignatureParameters param in paramSets)
                Encode(param);
        }

        private void Encode(SignatureParameters param)
        {
            NtruSign ntru = new NtruSign(param);
            SignatureKeyPair kp = ntru.generateKeyPair();

            // encode to byte[] and reconstruct
            byte[] enc = kp.getEncoded();
            SignatureKeyPair kp2 = new SignatureKeyPair(enc);
            Assert.Equals(kp, kp2);

            // encode to OutputStream and reconstruct
            MemoryStream bos = new MemoryStream();
            kp.writeTo(bos);
            MemoryStream bis = new MemoryStream(bos.ToArray());
            SignatureKeyPair kp3 = new SignatureKeyPair(bis);
            Assert.Equals(kp, kp3);
        }
        #endregion
    }
}