#region Directives
using System;
using Test.Tests.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Encode
{
    /// <summary>
    /// ArrayEncoder test
    /// </summary>
    public class ArrayEncoderTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the ArrayEncoder implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! ArrayEncoder tests have executed succesfully.";
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
        /// Test the validity of the ArrayEncoder implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                EncodeDecodeModQ();
                OnProgress(new TestEventArgs("Passed ArrayEncoder EncodeDecodeModQ"));
                EncodeDecodeMod3Sves();
                OnProgress(new TestEventArgs("Passed ArrayEncoder EncodeDecodeMod3Sves"));
                EncodeDecodeMod3Tight();
                OnProgress(new TestEventArgs("Passed ArrayEncoder EncodeDecodeMod3Tight"));

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
        private void EncodeDecodeModQ()
        {
            int[] coeffs = PolynomialGeneratorForTesting.generateRandomPositive(1000, 2048).Coeffs;
            byte[] data = ArrayEncoder.EncodeModQ(coeffs, 2048);
            int[] coeffs2 = ArrayEncoder.DecodeModQ(data, 1000, 2048);

            if (!Compare.AreEqual(coeffs, coeffs2))
                throw new Exception("ArrayEncoder EncodeDecodeModQ test failed!");
        }

        private void EncodeDecodeMod3Sves()
        {
            Random rng = new Random();
            bool[] skip = new bool[] { true, false };

            foreach (bool skipFirst in skip)
            {
                for (int i = 0; i < 10; i++)
                {
                    int N = (rng.Next(1000) + 100) * 16;
                    byte[] data = new byte[N * 3 / 16];
                    rng.NextBytes(data);
                    data[data.Length - 1] = 0;
                    int[] coeffs = ArrayEncoder.DecodeMod3Sves(data, N, skipFirst);
                    byte[] data2 = ArrayEncoder.EncodeMod3Sves(coeffs, skipFirst);
                    if (!Compare.AreEqual(data, data2))
                        throw new Exception("ArrayEncoder EncodeDecodeMod3Sves test failed!");
                }
            }
        }

        private void EncodeDecodeMod3Tight()
        {
            int[] coeffs = PolynomialGeneratorForTesting.generateRandom(1000).Coeffs;
            byte[] data = ArrayEncoder.EncodeMod3Tight(coeffs);
            int[] coeffs2 = ArrayEncoder.DecodeMod3Tight(data, 1000);

            if (!Compare.AreEqual(coeffs, coeffs2))
                throw new Exception("ArrayEncoder EncodeDecodeMod3Tight test failed!");
        }
        #endregion
    }
}