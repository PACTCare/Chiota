#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace Test.Tests.Encrypt
{
    /// <summary>
    /// Test the validity of the BitString implementation
    /// </summary>
    public class BitStringTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the BitString implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! BitString tests have executed succesfully.";
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
        /// BitString tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                AppendBitsByteArray();
                OnProgress(new TestEventArgs("Passed append bits to array test"));
                GetTrailing();
                OnProgress(new TestEventArgs("Passed get trailing bits test"));
                GetLeadingAsInt();
                OnProgress(new TestEventArgs("Passed leading as int tests"));

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
        private void AppendBitsByteArray()
        {
            IndexGenerator.BitString bs = new IndexGenerator.BitString();
            bs.AppendBits((byte)78);
            BitStringEquals(bs, new byte[] { 78 });
            bs.AppendBits(unchecked((byte)-5));
            BitStringEquals(bs, ByteUtils.ToBytes(new sbyte[] { 78, -5 }));
            bs.AppendBits((byte)127);
            BitStringEquals(bs, ByteUtils.ToBytes(new sbyte[] { 78, -5, 127 }));
            bs.AppendBits((byte)0);
            BitStringEquals(bs, ByteUtils.ToBytes(new sbyte[] { 78, -5, 127, 0 }));
            bs.AppendBits((byte)100);
            BitStringEquals(bs, ByteUtils.ToBytes(new sbyte[] { 78, -5, 127, 0, 100 }));
        }

        private void BitStringEquals(IndexGenerator.BitString bs, byte[] arr)
        {
            if (bs.Bytes.Length < arr.Length)
                throw new Exception("BitString equality test failed!");

            arr = arr.CopyOf(bs.Bytes.Length);
            if (!Compare.AreEqual(arr, bs.Bytes))
                throw new Exception("BitString equality test failed!");
        }

        private void GetTrailing()
        {
            IndexGenerator.BitString bs = new IndexGenerator.BitString();
            bs.AppendBits((byte)78);
            IndexGenerator.BitString bs2 = bs.GetTrailing(3);
            BitStringEquals(bs2, new byte[] { 6 });

            bs = new IndexGenerator.BitString();
            bs.AppendBits((byte)78);
            bs.AppendBits(unchecked((byte)-5));
            bs2 = bs.GetTrailing(9);
            BitStringEquals(bs2, new byte[] { 78, 1 });

            bs2.AppendBits((byte)100);
            BitStringEquals(bs2, ByteUtils.ToBytes(new sbyte[] { 78, -55 }));
            bs = bs2.GetTrailing(13);
            BitStringEquals(bs, new byte[] { 78, 9 });
            bs2 = bs2.GetTrailing(11);
            BitStringEquals(bs2, new byte[] { 78, 1 });

            bs2.AppendBits((byte)100);
            BitStringEquals(bs2, new byte[] { 78, 33, 3 });
            bs2 = bs2.GetTrailing(16);
            BitStringEquals(bs2, new byte[] { 78, 33 });
        }

        private void GetLeadingAsInt()
        {
            IndexGenerator.BitString bs = new IndexGenerator.BitString();
            bs.AppendBits((byte)78);
            bs.AppendBits((byte)42);
            if (!Compare.Equals(1, bs.GetLeadingAsInt(3)))
                throw new Exception("BitString LeadingAsInt test failed!");
            if (!Compare.Equals(84, bs.GetLeadingAsInt(9)))
                throw new Exception("BitString LeadingAsInt test failed!");
            if (!Compare.Equals(338, bs.GetLeadingAsInt(11)))
                throw new Exception("BitString LeadingAsInt test failed!");

            IndexGenerator.BitString bs2 = bs.GetTrailing(11);
            BitStringEquals(bs2, new byte[] { 78, 2 });
            if (!Compare.Equals(590, bs2.GetLeadingAsInt(11)))
                throw new Exception("BitString LeadingAsInt test failed!");
            if (!Compare.Equals(9, bs2.GetLeadingAsInt(5)))
                throw new Exception("BitString LeadingAsInt test failed!");

            bs2.AppendBits((byte)115);
            if (!Compare.Equals(230, bs2.GetLeadingAsInt(9)))
                throw new Exception("BitString LeadingAsInt test failed!");
            if (!Compare.Equals(922, bs2.GetLeadingAsInt(11)))
                throw new Exception("BitString LeadingAsInt test failed!");
            bs2.AppendBits(unchecked((byte)-36));
            if (!Compare.Equals(55, bs2.GetLeadingAsInt(6)))
                throw new Exception("BitString LeadingAsInt test failed!");
        }
        #endregion
    }
}