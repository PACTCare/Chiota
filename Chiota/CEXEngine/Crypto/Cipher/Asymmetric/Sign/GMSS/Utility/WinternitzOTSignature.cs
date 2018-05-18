#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility
{
    /// <summary>
    /// This class implements key pair generation and signature generation of the
    /// Winternitz one-time signature scheme (OTSS), described in C.Dods, N.P. Smart,
    /// and M. Stam, "Hash Based Digital Signature Schemes", LNCS 3796, pages
    /// 96&#8211;115, 2005. The class is used by the GMSS classes.
    /// </summary>
    internal sealed class WinternitzOTSignature
    {
        #region Fields
        // The hash function used by the OTS
        private IDigest _msgDigestOTS;
        //The length of the message digest and private key
        private int _mdsize;
        private int m_keySize;
        // The private key
        private byte[][] _privateKeyOTS;
        // The Winternitz parameter
        private int _W;
        // The source of randomness for OTS private key generation
        private GMSSRandom _gmssRandom;
        // Sizes of the message and the checksum, both
        private int _msgSize;
        private int _ckmSize;
        #endregion

        #region Constructor
        /// <summary>
        /// The constructor generates an OTS key pair, using <c>seed0</c> and the PRNG
        /// </summary>
        /// 
        /// <param name="Seed">The seed for the PRGN</param>
        /// <param name="Digest">The used hash function</param>
        /// <param name="W">The Winternitz parameter</param>
        public WinternitzOTSignature(byte[] Seed, IDigest Digest, int W)
        {
            _W = W;
            _msgDigestOTS = Digest;
            _gmssRandom = new GMSSRandom(_msgDigestOTS);
            // calulate keysize for private and public key and also the help array
            _mdsize = _msgDigestOTS.DigestSize;
            int mdsizeBit = _mdsize << 3;
            _msgSize = (int)Math.Ceiling((double)(mdsizeBit) / (double)W);
            _ckmSize = GetLog((_msgSize << W) + 1);
            m_keySize = _msgSize + (int)Math.Ceiling((double)_ckmSize / (double)W);
            // define the private key messagesize
            _privateKeyOTS = ArrayUtils.CreateJagged<byte[][]>(m_keySize, _mdsize);
            // gmssRandom.setSeed(seed0);
            byte[] dummy = new byte[_mdsize];
            Array.Copy(Seed, 0, dummy, 0, dummy.Length);

            // generate random bytes and assign them to the private key
            for (int i = 0; i < m_keySize; i++)
                _privateKeyOTS[i] = _gmssRandom.NextSeed(dummy);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// The private OTS key
        /// </summary>
        /// 
        /// <returns>The private key</returns>
        public byte[][] GetPrivateKey()
        {
            return _privateKeyOTS;
        }

        /// <summary>
        /// The public OTS key
        /// </summary>
        /// 
        /// <returns>The public key</returns>
        public byte[] GetPublicKey()
        {
            byte[] helppubKey = new byte[m_keySize * _mdsize];
            byte[] help = new byte[_mdsize];
            int two_power_t = 1 << _W;

            for (int i = 0; i < m_keySize; i++)
            {
                // hash w-1 time the private key and assign it to the public key
                _msgDigestOTS.BlockUpdate(_privateKeyOTS[i], 0, _privateKeyOTS[i].Length);
                help = new byte[_msgDigestOTS.DigestSize];
                _msgDigestOTS.DoFinal(help, 0);

                for (int j = 2; j < two_power_t; j++)
                {
                    _msgDigestOTS.BlockUpdate(help, 0, help.Length);
                    help = new byte[_msgDigestOTS.DigestSize];
                    _msgDigestOTS.DoFinal(help, 0);
                }

                Array.Copy(help, 0, helppubKey, _mdsize * i, _mdsize);
            }

            _msgDigestOTS.BlockUpdate(helppubKey, 0, helppubKey.Length);
            byte[] tmp = new byte[_msgDigestOTS.DigestSize];
            _msgDigestOTS.DoFinal(tmp, 0);

            return tmp;
        }
        
        /// <summary>
        /// The one-time signature of the message, generated with the private key
        /// </summary>
        /// 
        /// <param name="Message">The message</param>
        /// 
        /// <returns>The signature code</returns>
        public byte[] GetSignature(byte[] Message)
        {
            byte[] sign = new byte[m_keySize * _mdsize];
            // byte [] message; // message m as input
            byte[] hash = new byte[_mdsize]; // hash of message m
            int counter = 0;
            int c = 0;
            int test = 0;
            // create hash of message m
            _msgDigestOTS.BlockUpdate(Message, 0, Message.Length);
            hash = new byte[_msgDigestOTS.DigestSize];
            _msgDigestOTS.DoFinal(hash, 0);

            if (8 % _W == 0)
            {
                int d = 8 / _W;
                int k = (1 << _W) - 1;
                byte[] hlp = new byte[_mdsize];

                // create signature
                for (int i = 0; i < hash.Length; i++)
                {
                    for (int j = 0; j < d; j++)
                    {
                        test = hash[i] & k;
                        c += test;
                        Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);

                        while (test > 0)
                        {
                            _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                            hlp = new byte[_msgDigestOTS.DigestSize];
                            _msgDigestOTS.DoFinal(hlp, 0);
                            test--;
                        }
                        Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                        hash[i] = (byte)(IntUtils.URShift(hash[i], _W));
                        counter++;
                    }
                }

                c = (_msgSize << _W) - c;
                for (int i = 0; i < _ckmSize; i += _W)
                {
                    test = c & k;
                    Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);

                    while (test > 0)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test--;
                    }

                    Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                    c = IntUtils.URShift(c, _W);
                    counter++;
                }
            }
            else if (_W < 8)
            {
                int d = _mdsize / _W;
                int k = (1 << _W) - 1;
                byte[] hlp = new byte[_mdsize];
                long big8;
                int ii = 0;
                // create signature
                // first d*w bytes of hash
                for (int i = 0; i < d; i++)
                {
                    big8 = 0;
                    for (int j = 0; j < _W; j++)
                    {
                        big8 ^= (hash[ii] & 0xff) << (j << 3);
                        ii++;
                    }
                    for (int j = 0; j < 8; j++)
                    {
                        test = (int)(big8 & k);
                        c += test;

                        Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);

                        while (test > 0)
                        {
                            _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                            hlp = new byte[_msgDigestOTS.DigestSize];
                            _msgDigestOTS.DoFinal(hlp, 0);
                            test--;
                        }
                        Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                        big8 = IntUtils.URShift(big8, _W);
                        counter++;
                    }
                }
                // rest of hash
                d = _mdsize % _W;
                big8 = 0;
                for (int j = 0; j < d; j++)
                {
                    big8 ^= (hash[ii] & 0xff) << (j << 3);
                    ii++;
                }
                d <<= 3;
                for (int j = 0; j < d; j += _W)
                {
                    test = (int)(big8 & k);
                    c += test;

                    Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);

                    while (test > 0)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test--;
                    }
                    Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                    big8 = IntUtils.URShift(big8, _W);
                    counter++;
                }

                // check bytes
                c = (_msgSize << _W) - c;
                for (int i = 0; i < _ckmSize; i += _W)
                {
                    test = c & k;

                    Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);

                    while (test > 0)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test--;
                    }
                    Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                    c = IntUtils.URShift(c, _W);
                    counter++;
                }
            }// end if(w<8)
            else if (_W < 57)
            {
                int d = (_mdsize << 3) - _W;
                int k = (1 << _W) - 1;
                byte[] hlp = new byte[_mdsize];
                long big8, test8;
                int r = 0;
                int s, f, rest, ii;
                // create signature
                // first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w
                while (r <= d)
                {
                    s = IntUtils.URShift(r, 3);
                    rest = r % 8;
                    r += _W;
                    f = IntUtils.URShift((r + 7), 3);
                    big8 = 0;
                    ii = 0;
                    for (int j = s; j < f; j++)
                    {
                        big8 ^= (hash[j] & 0xff) << (ii << 3);
                        ii++;
                    }

                    big8 = IntUtils.URShift(big8, rest);
                    test8 = (big8 & k);
                    c += (int)test8;

                    Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);
                    while (test8 > 0)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test8--;
                    }
                    Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                    counter++;

                }
                // rest of hash
                s = IntUtils.URShift(r, 3);
                if (s < _mdsize)
                {
                    rest = r % 8;
                    big8 = 0;
                    ii = 0;
                    for (int j = s; j < _mdsize; j++)
                    {
                        big8 ^= (hash[j] & 0xff) << (ii << 3);
                        ii++;
                    }

                    big8 = IntUtils.URShift(big8, rest);
                    test8 = (big8 & k);
                    c += (int)test8;

                    Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);
                    while (test8 > 0)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test8--;
                    }

                    Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                    counter++;
                }
                // check bytes
                c = (_msgSize << _W) - c;
                for (int i = 0; i < _ckmSize; i += _W)
                {
                    test8 = (c & k);

                    Array.Copy(_privateKeyOTS[counter], 0, hlp, 0, _mdsize);

                    while (test8 > 0)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test8--;
                    }
                    Array.Copy(hlp, 0, sign, counter * _mdsize, _mdsize);
                    c = IntUtils.URShift(c, _W);
                    counter++;
                }
            }// end if(w<57)

            return sign;
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
        #endregion
    }
}
