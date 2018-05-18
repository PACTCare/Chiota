#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic
{
    /// <summary>
    /// This class implements the distributed computation of the public key of the
    /// Winternitz one-time signature scheme (OTSS). The class is used by the GMSS
    /// classes for calculation of upcoming leafs.
    /// </summary>
    internal sealed class GMSSLeaf : IDisposable
    {
        #region Fields
        // The hash function used by the OTS and the PRNG
        private IDigest _msgDigestOTS;
        // The length of the message digest and private key
        private int _mdsize;
        private int m_keySize;
        // The source of randomness for OTS private key generation
        private GMSSRandom _gmssRandom;
        // Byte array for distributed computation of the upcoming leaf
        private byte[] _leaf;
        // Byte array for storing the concatenated hashes of private key parts
        private byte[] _concHashs;
        // indices for distributed computation
        private int _ctr1;
        private int _ctr2;
        // storing 2^w
        private int _twoPowerW;
        // Winternitz parameter w
        private int _W;
        // the amount of distributed computation steps when updateLeaf is called
        private int _steps;
        // the internal seed
        private byte[] _seed;
        // the OTS privateKey parts
        private byte[] _privateKeyOTS;
        private bool m_isDisposed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// This constructor regenerates a prior GMSSLeaf object
        /// </summary>
        /// 
        /// <param name="Digest">The hash function</param>
        /// <param name="OtsIndex">The status bytes</param>
        /// <param name="NumLeafs">The status ints</param>
        public GMSSLeaf(IDigest Digest, byte[][] OtsIndex, int[] NumLeafs)
        {
            _ctr1 = NumLeafs[0];
            _ctr2 = NumLeafs[1];
            _steps = NumLeafs[2];
            _W = NumLeafs[3];
            _msgDigestOTS = Digest;
            _gmssRandom = new GMSSRandom(_msgDigestOTS);
            // calulate keysize for private key and the help array
            _mdsize = _msgDigestOTS.DigestSize;
            int mdsizeBit = _mdsize << 3;
            int messagesize = (int)Math.Ceiling((double)(mdsizeBit) / (double)_W);
            int checksumsize = GetLog((messagesize << _W) + 1);
            m_keySize = messagesize + (int)Math.Ceiling((double)checksumsize / (double)_W);
            _twoPowerW = 1 << _W;
            // initialize arrays
            _privateKeyOTS = OtsIndex[0];
            _seed = OtsIndex[1];
            _concHashs = OtsIndex[2];
            _leaf = OtsIndex[3];
        }

        /// <summary>
        /// The constructor precomputes some needed variables for distributed leaf calculation
        /// </summary>
        /// 
        /// <param name="Digest">The hash function</param>
        /// <param name="W">The winterniz parameter of that tree the leaf is computed for</param>
        /// <param name="NumLeafs">The number of leafs of the tree from where the distributed computation is called</param>
        internal GMSSLeaf(IDigest Digest, int W, int NumLeafs)
        {
            _W = W;
            _msgDigestOTS = Digest;
            _gmssRandom = new GMSSRandom(_msgDigestOTS);
            // calulate keysize for private key and the help array
            _mdsize = _msgDigestOTS.DigestSize;
            int mdsizeBit = _mdsize << 3;
            int messagesize = (int)Math.Ceiling((double)(mdsizeBit) / (double)W);
            int checksumsize = GetLog((messagesize << W) + 1);
            m_keySize = messagesize + (int)Math.Ceiling((double)checksumsize / (double)W);
            _twoPowerW = 1 << W;
            // calculate steps ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
            _steps = (int)Math.Ceiling((double)(((1 << W) - 1) * m_keySize + 1 + m_keySize) / (double)(NumLeafs));
            // initialize arrays
            _seed = new byte[_mdsize];
            _leaf = new byte[_mdsize];
            _privateKeyOTS = new byte[_mdsize];
            _concHashs = new byte[_mdsize * m_keySize];
        }
        
        /// <summary>
        /// The constructor precomputes some needed variables for distributed leaf calculation
        /// </summary>
        /// 
        /// <param name="Digest">The hash function</param>
        /// <param name="W">The winterniz parameter of that tree the leaf is computed for</param>
        /// <param name="NumLeafs">The number of leafs of the tree from where the distributed computation is called</param>
        /// <param name="Seed">The hash seed value</param>
        public GMSSLeaf(IDigest Digest, int W, int NumLeafs, byte[] Seed)
        {
            _W = W;
            _msgDigestOTS = Digest;
            _gmssRandom = new GMSSRandom(_msgDigestOTS);
            // calulate keysize for private key and the help array
            _mdsize = _msgDigestOTS.DigestSize;
            int mdsizeBit = _mdsize << 3;
            int messagesize = (int)Math.Ceiling((double)(mdsizeBit) / (double)W);
            int checksumsize = GetLog((messagesize << W) + 1);
            m_keySize = messagesize + (int)Math.Ceiling((double)checksumsize / (double)W);
            _twoPowerW = 1 << W;
            // calculate steps ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
            _steps = (int)Math.Ceiling((double)(((1 << W) - 1) * m_keySize + 1 + m_keySize) / (double)(NumLeafs));
            // initialize arrays
            _seed = new byte[_mdsize];
            _leaf = new byte[_mdsize];
            _privateKeyOTS = new byte[_mdsize];
            _concHashs = new byte[_mdsize * m_keySize];

            InitLeafCalc(Seed);
        }

        private GMSSLeaf(GMSSLeaf original)
        {
            _msgDigestOTS = original._msgDigestOTS;
            _mdsize = original._mdsize;
            m_keySize = original.m_keySize;
            _gmssRandom = original._gmssRandom;
            _leaf = ArrayUtils.Clone(original._leaf);
            _concHashs = ArrayUtils.Clone(original._concHashs);
            _ctr1 = original._ctr1;
            _ctr2 = original._ctr2;
            _twoPowerW = original._twoPowerW;
            _W = original._W;
            _steps = original._steps;
            _seed = ArrayUtils.Clone(original._seed);
            _privateKeyOTS = ArrayUtils.Clone(original._privateKeyOTS);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSLeaf()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns the leaf value
        /// </summary>
        /// 
        /// <returns>The leaf value</returns>
        public byte[] GetLeaf()
        {
            return ArrayUtils.Clone(_leaf);
        }

        /// <summary>
        /// Returns the status byte array used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <returns>The status bytes</returns>
        public byte[][] GetStatByte()
        {

            byte[][] statByte = new byte[4][];
            statByte[0] = new byte[_mdsize];
            statByte[1] = new byte[_mdsize];
            statByte[2] = new byte[_mdsize * m_keySize];
            statByte[3] = new byte[_mdsize];
            statByte[0] = _privateKeyOTS;
            statByte[1] = _seed;
            statByte[2] = _concHashs;
            statByte[3] = _leaf;

            return statByte;
        }

        /// <summary>
        /// Returns the status int array used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <returns>The status ints</returns>
        public int[] GetStatInt()
        {

            int[] statInt = new int[4];
            statInt[0] = _ctr1;
            statInt[1] = _ctr2;
            statInt[2] = _steps;
            statInt[3] = _W;

            return statInt;
        }

        /// <summary>
        /// Initialize the distributed leaf calculation reset i,j and compute OTSseed with seed0
        /// </summary>
        /// 
        /// <param name="Seed">The starting seed</param>
        public void InitLeafCalc(byte[] Seed)
        {
            _ctr1 = 0;
            _ctr2 = 0;
            byte[] dummy = new byte[_mdsize];
            Array.Copy(Seed, 0, dummy, 0, _seed.Length);
            _seed = _gmssRandom.NextSeed(dummy);
        }

        public GMSSLeaf NextLeaf()
        {
            GMSSLeaf nextLeaf = new GMSSLeaf(this);
            nextLeaf.UpdateLeafCalc();

            return nextLeaf;
        }

        /// <summary>
        /// Processes <c>steps</c> steps of distributed leaf calculation
        /// </summary>
        public void UpdateLeafCalc()
        {
            byte[] buf = new byte[_msgDigestOTS.DigestSize];

            // steps times do
            // TODO: this really needs to be looked at, the 10000 has been added as
            // prior to this the leaf value always ended up as zeros.
            for (int s = 0; s < _steps + 10000; s++)
            {
                if (_ctr1 == m_keySize && _ctr2 == _twoPowerW - 1)
                { 
                    // [3] at last hash the concatenation
                    _msgDigestOTS.BlockUpdate(_concHashs, 0, _concHashs.Length);
                    _leaf = new byte[_msgDigestOTS.DigestSize];
                    _msgDigestOTS.DoFinal(_leaf, 0);
                    return;
                }
                else if (_ctr1 == 0 || _ctr2 == _twoPowerW - 1)
                { 
                    // [1] at the beginning and when [2] is finished: get the next private key part
                    _ctr1++;
                    _ctr2 = 0;
                    // get next privKey part
                    _privateKeyOTS = _gmssRandom.NextSeed(_seed);
                }
                else
                { 
                    // [2] hash the privKey part
                    _msgDigestOTS.BlockUpdate(_privateKeyOTS, 0, _privateKeyOTS.Length);
                    _privateKeyOTS = buf;
                    _msgDigestOTS.DoFinal(_privateKeyOTS, 0);
                    _ctr2++;

                    // after w hashes add to the concatenated array
                    if (_ctr2 == _twoPowerW - 1)
                        Array.Copy(_privateKeyOTS, 0, _concHashs, _mdsize * (_ctr1 - 1), _mdsize);
                }
            }

            throw new Exception("unable to updateLeaf in steps: " + _steps + " " + _ctr1 + " " + _ctr2);
        }

        /// <summary>
        /// This method returns the least integer that is greater or equal to the logarithm to the base 2 of an integer <c>intValue</c>
        /// </summary>
        /// 
        /// <param name="Value">An integer</param>
        /// 
        /// <returns>The least integer greater or equal to the logarithm to the base 2 of <c>Value</c></returns>
        public int GetLog(int Value)
        {
            int log = 1;
            int i = 2;

            while (i < Value)
            {
                i <<= 1;
                log++;
            }

            return log;
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
                    if (_msgDigestOTS != null)
                    {
                        _msgDigestOTS.Dispose();
                        _msgDigestOTS = null;
                    }
                    if (_gmssRandom != null)
                    {
                        _gmssRandom.Dispose();
                        _gmssRandom = null;
                    }
                    if (_leaf != null)
                    {
                        Array.Clear(_leaf, 0, _leaf.Length);
                        _leaf = null;
                    }
                    if (_concHashs != null)
                    {
                        Array.Clear(_concHashs, 0, _concHashs.Length);
                        _concHashs = null;
                    }
                    if (_seed != null)
                    {
                        Array.Clear(_seed, 0, _seed.Length);
                        _seed = null;
                    }
                    if (_privateKeyOTS != null)
                    {
                        Array.Clear(_privateKeyOTS, 0, _privateKeyOTS.Length);
                        _privateKeyOTS = null;
                    }
                    _mdsize = 0;
                    m_keySize = 0;
                    _ctr1 = 0;
                    _ctr2 = 0;
                    _twoPowerW = 0;
                    _W = 0;
                    _steps = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
