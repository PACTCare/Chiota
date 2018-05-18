#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility
{
    /// <summary>
    /// This class provides a PRNG for GMSS
    /// </summary>
    internal sealed class GMSSRandom : IDisposable
    {
        #region Fields
        // Hash function for the construction of the authentication trees
        private IDigest _msgDigestTree;
        private bool m_isDisposed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="DigestTree">A hash digest instance</param>
        public GMSSRandom(IDigest DigestTree)
        {
            _msgDigestTree = DigestTree;
        }
        
        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSRandom()
        {
            Dispose(false);
        }
        #endregion

        #region Methods
        /// <summary>
        /// Computes the next seed value, returns a random byte array and sets outseed to the next value
        /// </summary>
        /// 
        /// <param name="OutSeed">A byte array in which ((1 + SEEDin +RAND) mod 2^n) will be</param>
        /// 
        /// <returns>Returns byte array of H(SEEDin)</returns>
        public byte[] NextSeed(byte[] OutSeed)
        {
            // RAND <-- H(SEEDin)
            byte[] rand = new byte[OutSeed.Length];
            _msgDigestTree.BlockUpdate(OutSeed, 0, OutSeed.Length);
            rand = new byte[_msgDigestTree.DigestSize];
            _msgDigestTree.DoFinal(rand, 0);

            // SEEDout <-- (1 + SEEDin +RAND) mod 2^n
            AddByteArrays(OutSeed, rand);
            AddOne(OutSeed);

            return rand;
        }

        private void AddByteArrays(byte[] A, byte[] B)
        {
            byte overflow = 0;
            int temp;

            for (int i = 0; i < A.Length; i++)
            {
                temp = (0xFF & A[i]) + (0xFF & B[i]) + overflow;
                A[i] = (byte)temp;
                overflow = (byte)(temp >> 8);
            }
        }

        private void AddOne(byte[] a)
        {
            byte overflow = 1;
            int temp;

            for (int i = 0; i < a.Length; i++)
            {
                temp = (0xFF & a[i]) + overflow;
                a[i] = (byte)temp;
                overflow = (byte)(temp >> 8);
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (_msgDigestTree != null)
                    {
                        _msgDigestTree.Dispose();
                        _msgDigestTree = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
