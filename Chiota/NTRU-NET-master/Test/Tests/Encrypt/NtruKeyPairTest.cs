#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Encrypt
{
    /// <summary>
    /// Test the validity of the NtruKeyPair implementation
    /// </summary>
    public class NtruKeyPairTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the NtruKeyPair implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! NtruKeyPair tests have executed succesfully.";
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
        /// NtruKeyPair tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                IsValid();
                OnProgress(new TestEventArgs("Passed generated key pair validation tests"));
                Encode();
                OnProgress(new TestEventArgs("Passed keypair encoding tests"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }

        private void IsValid()
        {
            // test valid key pairs
            NTRUParameters[] paramSets = new NTRUParameters[] 
            { 
                (NTRUParameters)NTRUParamSets.APR2011439.Clone(),
                (NTRUParameters)NTRUParamSets.APR2011439FAST.Clone(),
                (NTRUParameters)NTRUParamSets.APR2011743.Clone(),
                (NTRUParameters)NTRUParamSets.APR2011743FAST.Clone(),
                (NTRUParameters)NTRUParamSets.EES1087EP2.Clone(),
                (NTRUParameters)NTRUParamSets.EES1087EP2FAST.Clone(),
                (NTRUParameters)NTRUParamSets.EES1499EP1.Clone(),
                (NTRUParameters)NTRUParamSets.EES1499EP1FAST.Clone(),
            };

            foreach (NTRUParameters ep in paramSets)
            {
                NTRUKeyGenerator ntru = new NTRUKeyGenerator(ep);
                NTRUKeyPair kp1 = (NTRUKeyPair)ntru.GenerateKeyPair();
                if (!Compare.True(kp1.IsValid()))
                    throw new Exception("NtruKeyPair generated key pair is invalid!");
            }
        }

        private void Encode()
        {
            NTRUParameters[] paramSets = new NTRUParameters[] 
            {
                (NTRUParameters)NTRUParamSets.APR2011439.Clone(),
                (NTRUParameters)NTRUParamSets.APR2011439FAST.Clone(),
                (NTRUParameters)NTRUParamSets.APR2011743.Clone(),
                (NTRUParameters)NTRUParamSets.APR2011743FAST.Clone(),
                (NTRUParameters)NTRUParamSets.EES1087EP2.Clone(),
                (NTRUParameters)NTRUParamSets.EES1087EP2FAST.Clone(),
                (NTRUParameters)NTRUParamSets.EES1499EP1.Clone(),
                (NTRUParameters)NTRUParamSets.EES1499EP1FAST.Clone(),
            };

            foreach (NTRUParameters param in paramSets)
                Encode(param);
        }

        private void Encode(NTRUParameters param)
        {
            NTRUKeyPair kp;
            using (NTRUKeyGenerator kg = new NTRUKeyGenerator(param, false))
                kp = (NTRUKeyPair)kg.GenerateKeyPair();

            // encode to byte[] and reconstruct
            byte[] enc = kp.ToBytes();
            NTRUKeyPair kp2 = new NTRUKeyPair(enc);
            if (!Compare.Equals(kp, kp2))
                throw new Exception("NtruKeyPair encoding test failed!");

            // encode to OutputStream and reconstruct
            MemoryStream bos = new MemoryStream();
            kp.WriteTo(bos);
            MemoryStream bis = new MemoryStream(bos.ToArray());
            NTRUKeyPair kp3 = new NTRUKeyPair(bis);
            if (!Compare.Equals(kp, kp3))
                throw new Exception("NtruKeyPair encoding test failed!");
        }
        #endregion
    }
}