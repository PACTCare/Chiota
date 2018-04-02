#region Directives
using System;
using NTRU.Polynomial;
using NTRU.Sign;
using Numeric;
using Test.Tests.Misc;
#endregion

namespace Test.Tests.Sign
{
    public class NtruSignTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS!  tests have executed succesfully.";
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
                CreateBasis();
                OnProgress(new TestEventArgs("Passed .."));
                SignVerify();
                OnProgress(new TestEventArgs("Passed .."));
                InitUpdateSign();
                OnProgress(new TestEventArgs("Passed .."));
                CreateMsgRep();
                OnProgress(new TestEventArgs("Passed .."));
                GetOutputLength();
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
        private void CreateBasis()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157.Clone(), SignatureParameters.TEST157_PROD.Clone() })
                CreateBasis(param);
        }

        private void CreateBasis(SignatureParameters param)
        {
            NtruSign ntru = new NtruSign(param);
            FGBasis basis = (FGBasis)ntru.generateBoundedBasis();
            Assert.True(EqualsQ(basis.f, basis.fPrime, basis.F, basis.G, param.q, param.N));

            // test KeyGenAlg.FLOAT (default=RESULTANT)
            param.keyGenAlg = KeyGenAlg.FLOAT;
            ntru = new NtruSign(param);
            basis = (FGBasis)ntru.generateBoundedBasis();
            Assert.True(EqualsQ(basis.f, basis.fPrime, basis.F, basis.G, param.q, param.N));
        }

        // verifies that f*G-g*F=q
        private bool EqualsQ(NTRU.Polynomial.IPolynomial f, NTRU.Polynomial.IPolynomial g, IntegerPolynomial F, IntegerPolynomial G, int q, int N)
        {
            IntegerPolynomial x = f.Multiply(G);
            x.Subtract(g.Multiply(F));
            bool equalsQ = true;
            for (int i = 1; i < x.Coeffs.Length; i++)
                equalsQ &= x.Coeffs[i] == 0;
            equalsQ &= x.Coeffs[0] == q;
            return equalsQ;
        }

        /** a test for the one-method-call variants: sign(byte, SignatureKeyPair) and verify(byte[], byte[], SignatureKeyPair) */
        private void SignVerify()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157.Clone(), SignatureParameters.TEST157_PROD.Clone() })
                SignVerify(param);
        }

        private void SignVerify(SignatureParameters param)
        {
            NtruSign ntru = new NtruSign(param);
            SignatureKeyPair kp = ntru.generateKeyPair();
            Assert.Equals(param.B + 1, kp.priv.getNumBases());

            Random rng = new Random();
            byte[] msg = new byte[10 + rng.Next(1000)];
            rng.NextBytes(msg);

            // sign and verify
            byte[] s = ntru.sign(msg, kp);
            bool valid = ntru.verify(msg, s, kp.pub);
            Assert.True(valid);

            // altering the signature should make it invalid
            s[rng.Next(param.N)] += 1;
            valid = ntru.verify(msg, s, kp.pub);
            Assert.False(valid);

            // test that a random signature fails
            rng.NextBytes(s);
            valid = ntru.verify(msg, s, kp.pub);
            Assert.False(valid);

            // encode, decode keypair, test
            SignaturePrivateKey priv = new SignaturePrivateKey(kp.priv.getEncoded());
            SignaturePublicKey pub = new SignaturePublicKey(kp.pub.getEncoded());
            kp = new SignatureKeyPair(priv, pub);
            s = ntru.sign(msg, kp);
            valid = ntru.verify(msg, s, kp.pub);
            Assert.True(valid);

            // altering the signature should make it invalid
            s[rng.Next(s.Length)] += 1;
            valid = ntru.verify(msg, s, kp.pub);
            Assert.False(valid);

            // sparse/dense
            param.sparse = !param.sparse;
            s = ntru.sign(msg, kp);
            valid = ntru.verify(msg, s, kp.pub);
            Assert.True(valid);
            s[rng.Next(s.Length)] += 1;
            valid = ntru.verify(msg, s, kp.pub);
            Assert.False(valid);
            param.sparse = !param.sparse;

            // decrease NormBound to force multiple signing attempts
            SignatureParameters params2 = param.Clone();
            params2.normBoundSq *= (float)4.0 / 9;   // works for APR2011_439_PROD but may need to be increased for different params
            params2.signFailTolerance = 10000;
            ntru = new NtruSign(params2);
            s = ntru.sign(msg, kp);
            valid = ntru.verify(msg, s, kp.pub);
            Assert.True(valid);

            // test KeyGenAlg.FLOAT (default=RESULTANT)
            params2 = param.Clone();
            param.keyGenAlg = KeyGenAlg.FLOAT;
            ntru = new NtruSign(param);
            kp = ntru.generateKeyPair();
            s = ntru.sign(msg, kp);
            valid = ntru.verify(msg, s, kp.pub);
            Assert.True(valid);
            s[rng.Next(s.Length)] += 1;
            valid = ntru.verify(msg, s, kp.pub);
            Assert.False(valid);
        }

        /** test for the initSign/update/sign and initVerify/update/verify variant */
        private void InitUpdateSign()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157.Clone(), SignatureParameters.TEST157_PROD.Clone() })
                InitUpdateSign(param);
        }

        private void InitUpdateSign(SignatureParameters param)
        {
            NtruSign ntru = new NtruSign(param);

            SignatureKeyPair kp = ntru.generateKeyPair();

            Random rng = new Random();
            byte[] msg = new byte[10 + rng.Next(1000)];
            rng.NextBytes(msg);

            // sign and verify a message in two pieces each
            ntru.initSign(kp);
            int splitIdx = rng.Next(msg.Length);
            ntru.update(ArrayUtils.CopyOf(msg, splitIdx));   // part 1 of msg
            byte[] s = ntru.sign(ArrayUtils.CopyOfRange(msg, splitIdx, msg.Length));   // part 2 of msg
            ntru.initVerify(kp.pub);
            splitIdx = rng.Next(msg.Length);
            ntru.update(ArrayUtils.CopyOf(msg, splitIdx));   // part 1 of msg
            ntru.update(ArrayUtils.CopyOfRange(msg, splitIdx, msg.Length));   // part 2 of msg
            bool valid = ntru.verify(s);
            Assert.True(valid);
            // verify the same signature with the one-step method
            valid = ntru.verify(msg, s, kp.pub);
            Assert.True(valid);

            // sign using the one-step method and verify using the multi-step method
            s = ntru.sign(msg, kp);
            ntru.initVerify(kp.pub);
            splitIdx = rng.Next(msg.Length);
            ntru.update(ArrayUtils.CopyOf(msg, splitIdx));   // part 1 of msg
            ntru.update(ArrayUtils.CopyOfRange(msg, splitIdx, msg.Length));   // part 2 of msg
            valid = ntru.verify(s);
            Assert.True(valid);
        }

        private void CreateMsgRep()
        {
            foreach (SignatureParameters param in new SignatureParameters[] { SignatureParameters.TEST157.Clone(), SignatureParameters.TEST157_PROD.Clone() })
                CreateMsgRep(param);
        }

        private void CreateMsgRep(SignatureParameters param)
        {
            NtruSign ntru = new NtruSign(param);
            byte[] msgHash = ArrayUtils.ToBytes("adfsadfsdfs23234234");

            // verify that the message representative is reproducible
            IntegerPolynomial i1 = ntru.createMsgRep(msgHash, 1);
            IntegerPolynomial i2 = ntru.createMsgRep(msgHash, 1);
            Assert.ArrayEquals(i1.Coeffs, i2.Coeffs);
            i1 = ntru.createMsgRep(msgHash, 5);
            i2 = ntru.createMsgRep(msgHash, 5);
            Assert.ArrayEquals(i1.Coeffs, i2.Coeffs);

            i1 = ntru.createMsgRep(msgHash, 2);
            i2 = ntru.createMsgRep(msgHash, 3);
            Assert.False(Compare.AreEqual(i1.Coeffs, i2.Coeffs));
        }

        private void GetOutputLength()
        {
            SignatureParameters[] paramSets = new SignatureParameters[] { SignatureParameters.TEST157, SignatureParameters.TEST157_PROD, SignatureParameters.APR2011_439_PROD };
            byte[] msg = ArrayUtils.ToBytes("test message 12345");

            foreach (SignatureParameters param in paramSets)
            {
                NtruSign ntru = new NtruSign(param);
                SignatureKeyPair kp = ntru.generateKeyPair();
                byte[] s = ntru.sign(msg, kp);
                Assert.Equals(param.getOutputLength(), s.Length);
            }
        }
        #endregion
    }
}