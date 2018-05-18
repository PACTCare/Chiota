#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility
{
    /// <summary>
    /// This class implements signature verification of the Winternitz one-time
    /// signature scheme (OTSS), described in C.Dods, N.P. Smart, and M. Stam, "Hash
    /// Based Digital Signature Schemes", LNCS 3796, pages 96&#8211;115, 2005. 
    /// The class is used by the GMSS classes.
    /// </summary>
    internal sealed class WinternitzOTSVerify
    {
        #region Fields
        private IDigest _msgDigestOTS;
        private int _W;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Digest">The hash function used by the OTS and the provider</param>
        /// <param name="W">The Winternitz parameter</param>
        public WinternitzOTSVerify(IDigest Digest, int W)
        {
            _W = W;
            _msgDigestOTS = Digest;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// The length of the one-time signature
        /// </summary>
        /// 
        /// <returns>The signature length</returns>
        public int GetSignatureLength()
        {
            int mdsize = _msgDigestOTS.DigestSize;
            int size = ((mdsize << 3) + (_W - 1)) / _W;
            int logs = GetLog((size << _W) + 1);
            size += (logs + _W - 1) / _W;

            return mdsize * size;
        }

        /// <summary>
        /// This method computes the public OTS key from the one-time signature of a message.
        /// This is *NOT* a complete OTS signature verification, but it suffices for usage with CMSS.
        /// </summary>
        /// 
        /// <param name="Message">The message</param>
        /// <param name="Signature">The one-time signature</param>
        /// 
        /// <returns>The public OTS key</returns>
        public byte[] Verify(byte[] Message, byte[] Signature)
        {

            int mdsize = _msgDigestOTS.DigestSize;
            byte[] hash = new byte[mdsize]; // hash of message m

            // create hash of message m
            _msgDigestOTS.BlockUpdate(Message, 0, Message.Length);
            hash = new byte[_msgDigestOTS.DigestSize];
            _msgDigestOTS.DoFinal(hash, 0);

            int size = ((mdsize << 3) + (_W - 1)) / _W;
            int logs = GetLog((size << _W) + 1);
            int keysize = size + (logs + _W - 1) / _W;

            int testKeySize = mdsize * keysize;

            if (testKeySize != Signature.Length)
                return null;

            byte[] testKey = new byte[testKeySize];
            int c = 0;
            int counter = 0;
            int test;

            if (8 % _W == 0)
            {
                int d = 8 / _W;
                int k = (1 << _W) - 1;
                byte[] hlp = new byte[mdsize];

                // verify signature
                for (int i = 0; i < hash.Length; i++)
                {
                    for (int j = 0; j < d; j++)
                    {
                        test = hash[i] & k;
                        c += test;

                        Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                        while (test < k)
                        {
                            _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                            hlp = new byte[_msgDigestOTS.DigestSize];
                            _msgDigestOTS.DoFinal(hlp, 0);
                            test++;
                        }

                        Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                        hash[i] = (byte)(IntUtils.URShift(hash[i], _W));
                        counter++;
                    }
                }

                c = (size << _W) - c;
                for (int i = 0; i < logs; i += _W)
                {
                    test = c & k;

                    Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test++;
                    }
                    Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                    c = IntUtils.URShift(c, _W);
                    counter++;
                }
            }
            else if (_W < 8)
            {
                int d = mdsize / _W;
                int k = (1 << _W) - 1;
                byte[] hlp = new byte[mdsize];
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

                        Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                        while (test < k)
                        {
                            _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                            hlp = new byte[_msgDigestOTS.DigestSize];
                            _msgDigestOTS.DoFinal(hlp, 0);
                            test++;
                        }

                        Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                        big8 = IntUtils.URShift(big8, _W);
                        counter++;
                    }
                }
                // rest of hash
                d = mdsize % _W;
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

                    Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test++;
                    }

                    Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                    big8 = IntUtils.URShift(big8, _W);
                    counter++;
                }

                // check bytes
                c = (size << _W) - c;
                for (int i = 0; i < logs; i += _W)
                {
                    test = c & k;

                    Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test++;
                    }

                    Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                    c = IntUtils.URShift(c, _W);
                    counter++;
                }
            }// end if(w<8)
            else if (_W < 57)
            {
                int d = (mdsize << 3) - _W;
                int k = (1 << _W) - 1;
                byte[] hlp = new byte[mdsize];
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

                    Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                    while (test8 < k)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test8++;
                    }

                    Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                    counter++;

                }
                // rest of hash
                s = IntUtils.URShift(r, 3);
                if (s < mdsize)
                {
                    rest = r % 8;
                    big8 = 0;
                    ii = 0;
                    for (int j = s; j < mdsize; j++)
                    {
                        big8 ^= (hash[j] & 0xff) << (ii << 3);
                        ii++;
                    }

                    big8 = IntUtils.URShift(big8, rest);
                    test8 = (big8 & k);
                    c += (int)test8;

                    Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                    while (test8 < k)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test8++;
                    }

                    Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                    counter++;
                }
                // check bytes
                c = (size << _W) - c;
                for (int i = 0; i < logs; i += _W)
                {
                    test8 = (c & k);

                    Array.Copy(Signature, counter * mdsize, hlp, 0, mdsize);

                    while (test8 < k)
                    {
                        _msgDigestOTS.BlockUpdate(hlp, 0, hlp.Length);
                        hlp = new byte[_msgDigestOTS.DigestSize];
                        _msgDigestOTS.DoFinal(hlp, 0);
                        test8++;
                    }

                    Array.Copy(hlp, 0, testKey, counter * mdsize, mdsize);
                    c = IntUtils.URShift(c, _W);
                    counter++;
                }
            }// end if(w<57)

            byte[] TKey = new byte[mdsize];
            _msgDigestOTS.BlockUpdate(testKey, 0, testKey.Length);
            TKey = new byte[_msgDigestOTS.DigestSize];
            _msgDigestOTS.DoFinal(TKey, 0);

            return TKey;

        }

        /// <summary>
        /// This method returns the least integer that is greater or equal to the 
        /// logarithm to the base 2 of an integer <c>Value</c>
        /// </summary>
        /// 
        /// <param name="Value">An integer</param>
        /// 
        /// <returns>Return The least integer greater or equal to the logarithm to the base 256 of <c>Value</c></returns>
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
