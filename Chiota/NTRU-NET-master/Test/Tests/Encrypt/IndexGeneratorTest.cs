#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Encrypt
{
    /// <summary>
    /// Test the validity of the IndexGenerator implementation
    /// </summary>
    public class IndexGeneratorTest : ITest
    {
        #region Fields
        private NTRUParameters _parameters;
        private byte[] _seed;
        private IndexGenerator _gen;
        private int[] _indices;
        #endregion

        #region Constants
        private const string DESCRIPTION = "Test the validity of the IndexGenerator implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! IndexGenerator tests have executed succesfully.";
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
        /// IndexGenerator tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                Setup();
                Repeatability();
                OnProgress(new TestEventArgs("Passed index repeatability tests"));
                Range();
                OnProgress(new TestEventArgs("Passed index range tests"));

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
        private void Setup()
        {
            _seed = new byte[100];
            new Random().NextBytes(_seed);
            _parameters = NTRUParamSets.APR2011743;
            _gen = new IndexGenerator(_seed, _parameters);
            _indices = initIndices();
        }

        private int[] initIndices()
        {
            int[] indices = new int[1000];
            for (int i = 0; i < indices.Length; i++)
                indices[i] = _gen.NextIndex();

            return indices;
        }

        private void Repeatability()
        {
            _gen = new IndexGenerator(_seed, _parameters);
            int[] indices2 = initIndices();
            if (!Compare.AreEqual(_indices, indices2))
                throw new Exception("IndexGenerator repeatability test failed!");
        }

        private void Range()
        {
            foreach (int i in _indices)
            {
                if (!Compare.True(i >= 0 && i < _parameters.N))
                    throw new Exception("IndexGenerator range test failed!");
            }
        }
        #endregion
    }
}