#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic
{
    /// <summary>
    /// This class implements the distributed signature generation of the Winternitz
    /// one-time signature scheme (OTSS), described in C.Dods, N.P. Smart, and M.
    /// Stam, "Hash Based Digital Signature Schemes", LNCS 3796, pages 96&#8211;115,
    /// 2005. The class is used by the GMSS classes.
    /// </summary>
    internal sealed class GMSSRootSig : IDisposable
    {
        #region Fields
        // The hash function used by the OTS
        private IDigest _msgDigestOTS;
        // The length of the message digest and private key
        private int _mdSize;
        private int m_keySize;
        // The private key
        private byte[] _privateKeyOTS;
        // The message bytes
        private byte[] _msgHash;
        // The signature bytes
        private byte[] _sgnCode;
        // The Winternitz parameter
        private int _W;
        // The source of randomness for OTS private key generation
        private GMSSRandom _gmssRand;
        // Sizes of the message
        private int _msgSize;
        // Some precalculated values
        private int m_K;
        // Some variables for storing the actual status of distributed signing
        private int _R;
        private int _testCtr;
        private int _Counter;
        private int _iI;
        // variables for storing big numbers for the actual status of distributed signing
        private long _test8;
        private long _big8;
        // The necessary steps of each updateSign() call
        private int _steps;
        // The checksum part
        private int _chkSum;
        // The height of the tree
        private int _height;
        // The current intern OTSseed
        private byte[] _otsSeed;
        private bool m_isDisposed = false;
        #endregion
 
        #region Constructor
        /// <summary>
        /// This constructor regenerates a prior GMSSRootSig object used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <param name="Digest">The hash function</param>
        /// <param name="StatByte">The status byte array</param>
        /// <param name="StatInt">The status int array</param>
        public GMSSRootSig(IDigest Digest, byte[][] StatByte, int[] StatInt)
        {
            _msgDigestOTS = Digest;
            _gmssRand = new GMSSRandom(_msgDigestOTS);
            _Counter = StatInt[0];
            _testCtr = StatInt[1];
            _iI = StatInt[2];
            _R = StatInt[3];
            _steps = StatInt[4];
            m_keySize = StatInt[5];
            _height = StatInt[6];
            _W = StatInt[7];
            _chkSum = StatInt[8];
            _mdSize = _msgDigestOTS.DigestSize;
            m_K = (1 << _W) - 1;
            int mdsizeBit = _mdSize << 3;
            _msgSize = (int)Math.Ceiling((double)(mdsizeBit) / (double)_W);
            _privateKeyOTS = StatByte[0];
            _otsSeed = StatByte[1];
            _msgHash = StatByte[2];
            _sgnCode = StatByte[3];

            _test8 = ((StatByte[4][0] & 0xff)) | 
                ((byte)(StatByte[4][1] & 0xff) << 8) | 
                ((byte)(StatByte[4][2] & 0xff) << 16) | 
                ((byte)(StatByte[4][3] & 0xff)) << 24 | 
                ((byte)(StatByte[4][4] & 0xff)) << 32 | 
                ((byte)(StatByte[4][5] & 0xff)) << 40 | 
                ((byte)(StatByte[4][6] & 0xff)) << 48 | 
                ((byte)(StatByte[4][7] & 0xff)) << 56;

            _big8 = ((StatByte[4][8] & 0xff)) | 
                ((byte)(StatByte[4][9] & 0xff) << 8) | 
                ((byte)(StatByte[4][10] & 0xff) << 16) | 
                ((byte)(StatByte[4][11] & 0xff)) << 24 | 
                ((byte)(StatByte[4][12] & 0xff)) << 32 | 
                ((byte)(StatByte[4][13] & 0xff)) << 40 | 
                ((byte)(StatByte[4][14] & 0xff)) << 48 | 
                ((byte)(StatByte[4][15] & 0xff)) << 56;
        }

        /// <summary>
        /// The constructor generates the PRNG and initializes some variables
        /// </summary>
        /// 
        /// <param name="Digest">The hash function</param>
        /// <param name="W">The winternitz parameter</param>
        /// <param name="Height">The heigth of the tree</param>
        public GMSSRootSig(IDigest Digest, int W, int Height)
        {
            _msgDigestOTS = Digest;
            _gmssRand = new GMSSRandom(_msgDigestOTS);
            _mdSize = _msgDigestOTS.DigestSize;
            _W = W;
            _height = Height;
            m_K = (1 << W) - 1;
            int mdsizeBit = _mdSize << 3;
            _msgSize = (int)Math.Ceiling((double)(mdsizeBit) / (double)W);
        }
                
        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSRootSig()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// This method initializes the distributed sigature calculation.
        /// Variables are reseted and necessary steps are calculated.
        /// </summary>
        /// 
        /// <param name="Seed">The initial OTSseed</param>
        /// <param name="Message">The massage which will be signed</param>
        public void InitSign(byte[] Seed, byte[] Message)
        {

            // create hash of message m
            _msgHash = new byte[_mdSize];
            _msgDigestOTS.BlockUpdate(Message, 0, Message.Length);
            _msgHash = new byte[_msgDigestOTS.DigestSize];
            _msgDigestOTS.DoFinal(_msgHash, 0);
            // variables for calculation of steps
            byte[] messPart = new byte[_mdSize];
            Array.Copy(_msgHash, 0, messPart, 0, _mdSize);
            int checkPart = 0;
            int sumH = 0;
            int checksumsize = GetLog((_msgSize << _W) + 1);

            if (8 % _W == 0)
            {
                int dt = 8 / _W;
                // message part
                for (int a = 0; a < _mdSize; a++)
                {
                    // count necessary hashs in 'sumH'
                    for (int b = 0; b < dt; b++)
                    {
                        sumH += messPart[a] & m_K;
                        messPart[a] = (byte)(IntUtils.URShift(messPart[a], _W));
                    }
                }
                // checksum part
                _chkSum = (_msgSize << _W) - sumH;
                checkPart = _chkSum;
                // count necessary hashs in 'sumH'
                for (int b = 0; b < checksumsize; b += _W)
                {
                    sumH += checkPart & m_K;
                    checkPart = IntUtils.URShift(checkPart, _W);
                }
            } 
            else if (_W < 8)
            {
                long big8;
                int ii = 0;
                int dt = _mdSize / _W;

                // first d*w bytes of hash (main message part)
                for (int i = 0; i < dt; i++)
                {
                    big8 = 0;
                    for (int j = 0; j < _W; j++)
                    {
                        big8 ^= (messPart[ii] & 0xff) << (j << 3);
                        ii++;
                    }
                    // count necessary hashs in 'sumH'
                    for (int j = 0; j < 8; j++)
                    {
                        sumH += (int)(big8 & m_K);
                        big8 = IntUtils.URShift(big8, _W);
                    }
                }

                // rest of message part
                dt = _mdSize % _W;
                big8 = 0;
                for (int j = 0; j < dt; j++)
                {
                    big8 ^= (messPart[ii] & 0xff) << (j << 3);
                    ii++;
                }

                dt <<= 3;
                // count necessary hashs in 'sumH'
                for (int j = 0; j < dt; j += _W)
                {
                    sumH += (int)(big8 & m_K);
                    big8 = IntUtils.URShift(big8, _W);
                }

                // checksum part
                _chkSum = (_msgSize << _W) - sumH;
                checkPart = _chkSum;
                // count necessary hashs in 'sumH'
                for (int i = 0; i < checksumsize; i += _W)
                {
                    sumH += checkPart & m_K;
                    checkPart = IntUtils.URShift(checkPart, _W);
                }
            }
            else if (_W < 57)
            {
                long big8;
                int r = 0;
                int s, f, rest, ii;

                // first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w (main message part)
                while (r <= ((_mdSize << 3) - _W))
                {
                    s = IntUtils.URShift(r, 3);
                    rest = r % 8;
                    r += _W;
                    f = IntUtils.URShift((r + 7), 3);
                    big8 = 0;
                    ii = 0;

                    for (int j = s; j < f; j++)
                    {
                        big8 ^= (messPart[j] & 0xff) << (ii << 3);
                        ii++;
                    }

                    big8 = IntUtils.URShift(big8, rest);
                    // count necessary hashs in 'sumH'
                    sumH += ((int)big8 & m_K);

                }
                // rest of message part
                s = IntUtils.URShift(r, 3);
                if (s < _mdSize)
                {
                    rest = r % 8;
                    big8 = 0;
                    ii = 0;

                    for (int j = s; j < _mdSize; j++)
                    {
                        big8 ^= (messPart[j] & 0xff) << (ii << 3);
                        ii++;
                    }

                    big8 = IntUtils.URShift(big8, rest);
                    // count necessary hashs in 'sumH'
                    sumH += ((int)big8 & m_K);
                }
                // checksum part
                _chkSum = (_msgSize << _W) - sumH;
                checkPart = _chkSum;

                // count necessary hashs in 'sumH'
                for (int i = 0; i < checksumsize; i += _W)
                {
                    sumH += (checkPart & m_K);
                    checkPart = IntUtils.URShift(checkPart, _W);
                }
            }

            // calculate keysize
            m_keySize = _msgSize + (int)Math.Ceiling((double)checksumsize / (double)_W);
            // calculate steps: 'keysize' times PRNG, 'sumH' times hashing, (1<<height)-1 updateSign() calls
            _steps = (int)Math.Ceiling((double)(m_keySize + sumH) / (double)((1 << _height)));
            // reset variables
            _sgnCode = new byte[m_keySize * _mdSize];
            _Counter = 0;
            _testCtr = 0;
            _iI = 0;
            _test8 = 0;
            _R = 0;
            // define the private key messagesize
            _privateKeyOTS = new byte[_mdSize];
            // copy the seed
            _otsSeed = new byte[_mdSize];
            Array.Copy(Seed, 0, _otsSeed, 0, _mdSize);
        }

        /// <summary>
        /// This Method performs <c>steps</c> steps of distributed signature calculaion
        /// </summary>
        /// 
        /// <returns>Return true if signature is generated completly, else false</returns>
        public bool UpdateSign()
        {
            // steps times do
            for (int s = 0; s < _steps; s++)
            {
                // generate the private key or perform the next hash
                if (_Counter < m_keySize)
                    OneStep();
                
                if (_Counter == m_keySize)
                    return true;
            }

            // leaf not finished yet
            return false; 
        }
        
        /// <summary>
        /// Return private OTS key
        /// </summary>
        /// 
        /// <returns>The private OTS key</returns>
        public byte[] GetSig()
        {
            return _sgnCode;
        }

        /// <summary>
        /// Return The one-time signature of the message, generated step by step
        /// </summary>
        private void OneStep()
        {
            if (8 % _W == 0)
            {
                if (_testCtr == 0)
                {
                    // get current OTSprivateKey
                    _privateKeyOTS = _gmssRand.NextSeed(_otsSeed);

                    if (_iI < _mdSize)
                    { 
                        // for main message part
                        _testCtr = _msgHash[_iI] & m_K;
                        _msgHash[_iI] = (byte)(IntUtils.URShift(_msgHash[_iI], _W));
                    }
                    else
                    { 
                        // for checksum part
                        _testCtr = _chkSum & m_K;
                        _chkSum = IntUtils.URShift(_chkSum, _W);
                    }
                }
                else if (_testCtr > 0)
                { 
                    // hash the private Key 'test' times (on time each step)
                    _msgDigestOTS.BlockUpdate(_privateKeyOTS, 0, _privateKeyOTS.Length);
                    _privateKeyOTS = new byte[_msgDigestOTS.DigestSize];
                    _msgDigestOTS.DoFinal(_privateKeyOTS, 0);
                    _testCtr--;
                }

                if (_testCtr == 0)
                { 
                    // if all hashes done copy result to siganture array
                    Array.Copy(_privateKeyOTS, 0, _sgnCode, _Counter * _mdSize, _mdSize);
                    _Counter++;

                    // raise array index for main massage part
                    if (_Counter % (8 / _W) == 0)
                        _iI++;
                }

            }
            else if (_W < 8)
            {
                if (_testCtr == 0)
                {
                    if (_Counter % 8 == 0 && _iI < _mdSize)
                    { 
                        // after every 8th "add to signature"-step
                        _big8 = 0;
                        if (_Counter < ((_mdSize / _W) << 3))
                        {
                            // main massage (generate w*8 Bits every time) part
                            for (int j = 0; j < _W; j++)
                            {
                                _big8 ^= (_msgHash[_iI] & 0xff) << (j << 3);
                                _iI++;
                            }
                        }
                        else
                        { 
                            // rest of massage part (once)
                            for (int j = 0; j < _mdSize % _W; j++)
                            {
                                _big8 ^= (_msgHash[_iI] & 0xff) << (j << 3);
                                _iI++;
                            }
                        }
                    }

                    // checksum part (once)
                    if (_Counter == _msgSize)
                        _big8 = _chkSum;

                    _testCtr = (int)(_big8 & m_K);
                    // generate current OTSprivateKey
                    _privateKeyOTS = _gmssRand.NextSeed(_otsSeed);
                }
                else if (_testCtr > 0)
                {
                    // hash the private Key 'test' times (on time each step)
                    _msgDigestOTS.BlockUpdate(_privateKeyOTS, 0, _privateKeyOTS.Length);
                    _privateKeyOTS = new byte[_msgDigestOTS.DigestSize];
                    _msgDigestOTS.DoFinal(_privateKeyOTS, 0);
                    _testCtr--;
                }
                if (_testCtr == 0)
                {
                    // if all hashes done copy result to siganture array
                    Array.Copy(_privateKeyOTS, 0, _sgnCode, _Counter * _mdSize,_mdSize);
                    _big8 = IntUtils.URShift(_big8, _W);
                    _Counter++;
                }

            }
            else if (_W < 57)
            {
                if (_test8 == 0)
                {
                    int s, f, rest;
                    _big8 = 0;
                    _iI = 0;
                    rest = _R % 8;
                    s = IntUtils.URShift(_R, 3);
                    // message part
                    if (s < _mdSize)
                    {
                        if (_R <= ((_mdSize << 3) - _W))
                        { 
                            // first message part
                            _R += _W;
                            f = IntUtils.URShift((_R + 7), 3);
                        }
                        else
                        { 
                            // rest of message part (once)
                            f = _mdSize;
                            _R += _W;
                        }
                        // generate long 'big8' with minimum w next bits of the message array
                        for (int i = s; i < f; i++)
                        {
                            _big8 ^= (_msgHash[i] & 0xff) << (_iI << 3);
                            _iI++;
                        }
                        // delete bits on the right side, which were used already by the last loop
                        _big8 = IntUtils.URShift(_big8, rest);
                        _test8 = (_big8 & m_K);
                    }
                    // checksum part
                    else
                    {
                        _test8 = (_chkSum & m_K);
                        _chkSum = IntUtils.URShift(_chkSum, _W);
                    }
                    // generate current OTSprivateKey
                    _privateKeyOTS = _gmssRand.NextSeed(_otsSeed);
                }
                else if (_test8 > 0)
                {
                    // hash the private Key 'test' times (on time each step)
                    _msgDigestOTS.BlockUpdate(_privateKeyOTS, 0, _privateKeyOTS.Length);
                    _privateKeyOTS = new byte[_msgDigestOTS.DigestSize];
                    _msgDigestOTS.DoFinal(_privateKeyOTS, 0);
                    _test8--;
                }
                if (_test8 == 0)
                {
                    // if all hashes done copy result to siganture array
                    Array.Copy(_privateKeyOTS, 0, _sgnCode, _Counter * _mdSize, _mdSize);
                    _Counter++;
                }

            }
        }

        /// <summary>
        /// This method returns the least integer that is greater or equal to the logarithm to the base 2 of an integer <c>Value</c>
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

        /// <summary>
        /// This method returns the status byte array
        /// </summary>
        /// 
        /// <returns>Return statBytes</returns>
        public byte[][] GetStatByte()
        {
            byte[][] statByte = ArrayUtils.CreateJagged<byte[][]>(5, _mdSize);
            statByte[0] = _privateKeyOTS;
            statByte[1] = _otsSeed;
            statByte[2] = _msgHash;
            statByte[3] = _sgnCode;
            statByte[4] = GetStatLong();

            return statByte;
        }

        /// <summary>
        /// This method returns the status int array
        /// </summary>
        /// 
        /// <returns>Return statInt</returns>
        public int[] GetStatInt()
        {
            int[] statInt = new int[9];
            statInt[0] = _Counter;
            statInt[1] = _testCtr;
            statInt[2] = _iI;
            statInt[3] = _R;
            statInt[4] = _steps;
            statInt[5] = m_keySize;
            statInt[6] = _height;
            statInt[7] = _W;
            statInt[8] = _chkSum;

            return statInt;
        }

        /// <summary>
        /// Converts the long parameters into byte arrays to store it in statByte array
        /// </summary>
        /// 
        /// <returns>Return statByte array</returns>
        public byte[] GetStatLong()
        {
            byte[] bytes = new byte[16];

            bytes[0] = (byte)((_test8) & 0xff);
            bytes[1] = (byte)((_test8 >> 8) & 0xff);
            bytes[2] = (byte)((_test8 >> 16) & 0xff);
            bytes[3] = (byte)((_test8 >> 24) & 0xff);
            bytes[4] = (byte)((_test8) >> 32 & 0xff);
            bytes[5] = (byte)((_test8 >> 40) & 0xff);
            bytes[6] = (byte)((_test8 >> 48) & 0xff);
            bytes[7] = (byte)((_test8 >> 56) & 0xff);
            bytes[8] = (byte)((_big8) & 0xff);
            bytes[9] = (byte)((_big8 >> 8) & 0xff);
            bytes[10] = (byte)((_big8 >> 16) & 0xff);
            bytes[11] = (byte)((_big8 >> 24) & 0xff);
            bytes[12] = (byte)((_big8) >> 32 & 0xff);
            bytes[13] = (byte)((_big8 >> 40) & 0xff);
            bytes[14] = (byte)((_big8 >> 48) & 0xff);
            bytes[15] = (byte)((_big8 >> 56) & 0xff);

            return bytes;
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
                    if (_privateKeyOTS != null)
                    {
                        Array.Clear(_privateKeyOTS, 0, _privateKeyOTS.Length);
                        _privateKeyOTS = null;
                    }
                    if (_msgHash != null)
                    {
                        Array.Clear(_msgHash, 0, _msgHash.Length);
                        _msgHash = null;
                    }
                    if (_sgnCode != null)
                    {
                        Array.Clear(_sgnCode, 0, _sgnCode.Length);
                        _sgnCode = null;
                    }
                    if (_gmssRand != null)
                    {
                        _gmssRand.Dispose();
                        _gmssRand = null;
                    }
                    if (_otsSeed != null)
                    {
                        Array.Clear(_otsSeed, 0, _otsSeed.Length);
                        _otsSeed = null;
                    }
                    _mdSize = 0;
                    m_keySize = 0;
                    _W = 0;
                    _msgSize = 0;
                    m_K = 0;
                    _R = 0;
                    _testCtr = 0;
                    _Counter = 0;
                    _iI = 0;
                    _test8 = 0;
                    _big8 = 0;
                    _steps = 0;
                    _chkSum = 0;
                    _height = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
