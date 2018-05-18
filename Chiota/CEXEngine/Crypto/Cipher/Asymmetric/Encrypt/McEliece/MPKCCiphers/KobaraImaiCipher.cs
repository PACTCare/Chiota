#region Directives
using System;
using System.IO;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// This class implements the Kobara/Imai conversion of the McEliecePKCS.
    /// <para>This is  a conversion of the McEliecePKCS which is CCA2-secure.</para>
    /// </summary>
    internal class KobaraImaiCipher : IMPKCCiphers, IDisposable
    {
        #region Constants
        /// <summary>
        /// The algorithm identifier
        /// </summary>
        public static readonly byte[] OID = System.Text.Encoding.ASCII.GetBytes("1.3.6.1.4.1.8301.3.1.3.4.2.3");
        /// <summary>
        /// Configurable nonce, can create a unique distribution
        /// </summary>
        public static byte[] MPKCINFO = Encoding.ASCII.GetBytes("VTDev.CEX.McEliece version 1.0.1.0");
        #endregion

        #region Fields
        private IAsymmetricKey m_asmKey;
        private MPKCParameters m_cprParams;
        private IDigest m_dgtEngine;
        private bool m_isDisposed = false;
        private bool m_isEncryption = false;
        private int m_maxPlainText;
        private IRandom m_rndEngine;
        private int m_K;
        private int m_N;
        private int m_T;
        #endregion

        #region Properties

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        public int MaxPlainText
        {
            get { return m_maxPlainText; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher parameters</param>
        /// <param name="Info">The predefined nonce value</param>
        public KobaraImaiCipher(MPKCParameters Parameters, byte[] Info = null)
        {
            if (Info != null)
                KobaraImaiCipher.MPKCINFO = Info;

            m_cprParams = Parameters;
            m_dgtEngine = GetDigest(Parameters.Digest);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~KobaraImaiCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        public byte[] Decrypt(byte[] Input)
        {
            if (m_isEncryption)
                throw new CryptoAsymmetricException("KobaraImaiCipher:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            int nDiv8 = m_N >> 3;

            if (Input.Length < nDiv8)
                throw new CryptoAsymmetricException("KobaraImaiCipher:Decrypt", "Bad Padding: Ciphertext too short!", new ArgumentException());

            int c2Len = m_dgtEngine.DigestSize;
            int c4Len = m_K >> 3;
            int c6Len = Input.Length - nDiv8;

            // split cipher text (c6||encC4), where c6 may be empty
            byte[] c6, encC4;
            if (c6Len > 0)
            {
                byte[][] c6EncC4 = ByteUtils.Split(Input, c6Len);
                c6 = c6EncC4[0];
                encC4 = c6EncC4[1];
            }
            else
            {
                c6 = new byte[0];
                encC4 = Input;
            }

            // convert encC4 into vector over GF(2)
            GF2Vector encC4Vec = GF2Vector.OS2VP(m_N, encC4);
            // decrypt encC4Vec to obtain c4 and error vector z
            GF2Vector[] c4z = CCA2Primitives.Decrypt((MPKCPrivateKey)m_asmKey, encC4Vec);
            byte[] c4 = c4z[0].GetEncoded();
            GF2Vector z = c4z[1];

            // if length of c4 is greater than c4Len (because of padding), truncate the padding bytes
            if (c4.Length > c4Len)
                c4 = ByteUtils.SubArray(c4, 0, c4Len);

            // compute c5 = Conv^-1(z)
            byte[] c5 = CCA2Conversions.Decode(m_N, m_T, z);
            // compute (c6||c5||c4)
            byte[] c6c5c4 = ByteUtils.Concatenate(c6, c5);
            c6c5c4 = ByteUtils.Concatenate(c6c5c4, c4);

            // split (c6||c5||c4) into (c2||c1), where c2Len = mdLen and c1Len = input.length-c2Len bytes.
            int c1Len = c6c5c4.Length - c2Len;
            byte[][] c2c1 = ByteUtils.Split(c6c5c4, c2Len);
            byte[] c2 = c2c1[0];
            byte[] c1 = c2c1[1];

            // compute H(c1) ...
            byte[] rPrime = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.BlockUpdate(c1, 0, c1.Length);
            m_dgtEngine.DoFinal(rPrime, 0);

            // ... and XOR with c2 to obtain r'
            for (int i = c2Len - 1; i >= 0; i--)
                rPrime[i] ^= c2[i];

            byte[] mConstPrime;
            // get PRNG object
            using (KDF2 sr0 = new KDF2(GetDigest(m_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rPrime);
                // generate random sequence R(r') ...
                mConstPrime = new byte[c1Len];
                sr0.Generate(mConstPrime);
            }

            // ... and XOR with c1 to obtain (m||const')
            for (int i = c1Len - 1; i >= 0; i--)
                mConstPrime[i] ^= c1[i];

            if (mConstPrime.Length < c1Len)
                throw new CryptoAsymmetricException("KobaraImaiCipher:Decrypt", "Bad Padding: invalid ciphertext!", new ArgumentException());

            byte[][] temp = ByteUtils.Split(mConstPrime, c1Len - MPKCINFO.Length);
            byte[] mr = temp[0];
            byte[] constPrime = temp[1];

            if (!ByteUtils.Equals(constPrime, MPKCINFO))
                throw new CryptoAsymmetricException("KobaraImaiCipher:Decrypt", "Bad Padding: invalid ciphertext!", new ArgumentException());

            return mr;
        }

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        public byte[] Encrypt(byte[] Input)
        {
            if (!m_isEncryption)
                throw new CryptoAsymmetricException("KobaraImaiCipher:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            int c2Len = m_dgtEngine.DigestSize;
            int c4Len = m_K >> 3;
            int c5Len = (BigMath.Binomial(m_N, m_T).BitLength - 1) >> 3;
            int mLen = c4Len + c5Len - c2Len - MPKCINFO.Length;

            if (Input.Length > mLen)
                mLen = Input.Length;

            int c1Len = mLen + MPKCINFO.Length;
            int c6Len = c1Len + c2Len - c4Len - c5Len;

            // compute (m||const)
            byte[] mConst = new byte[c1Len];
            Array.Copy(Input, 0, mConst, 0, Input.Length);
            Array.Copy(MPKCINFO, 0, mConst, mLen, MPKCINFO.Length);

            // generate random r of length c2Len bytes
            byte[] r = new byte[c2Len];
            m_rndEngine.GetBytes(r);

            byte[] c1;
            // get PRNG object ToDo:
            //DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest()); //why bc, why?
            using (KDF2 sr0 = new KDF2(GetDigest(m_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(r);
                // generate random sequence ...
                c1 = new byte[c1Len];
                sr0.Generate(c1);
            }

            // ... and XOR with (m||const) to obtain c1
            for (int i = c1Len - 1; i >= 0; i--)
                c1[i] ^= mConst[i];

            // compute H(c1) ...
            byte[] c2 = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.BlockUpdate(c1, 0, c1.Length);
            m_dgtEngine.DoFinal(c2, 0);

            // ... and XOR with r
            for (int i = c2Len - 1; i >= 0; i--)
                c2[i] ^= r[i];

            // compute (c2||c1)
            byte[] c2c1 = ByteUtils.Concatenate(c2, c1);

            // split (c2||c1) into (c6||c5||c4), where c4Len is k/8 bytes, c5Len is
            // floor[log(n|t)]/8 bytes, and c6Len is c1Len+c2Len-c4Len-c5Len (may be 0).
            byte[] c6 = new byte[0];
            if (c6Len > 0)
            {
                c6 = new byte[c6Len];
                Array.Copy(c2c1, 0, c6, 0, c6Len);
            }

            byte[] c5 = new byte[c5Len];
            Array.Copy(c2c1, c6Len, c5, 0, c5Len);
            byte[] c4 = new byte[c4Len];
            Array.Copy(c2c1, c6Len + c5Len, c4, 0, c4Len);
            // convert c4 to vector over GF(2)
            GF2Vector c4Vec = GF2Vector.OS2VP(m_K, c4);
            // convert c5 to error vector z
            GF2Vector z = CCA2Conversions.Encode(m_N, m_T, c5);
            // compute encC4 = E(c4, z)
            byte[] encC4 = CCA2Primitives.Encrypt((MPKCPublicKey)m_asmKey, c4Vec, z).GetEncoded();

            // if c6Len > 0 return (c6||encC4)
            if (c6Len > 0)
                return ByteUtils.Concatenate(c6, encC4);

            // else, return encC4
            return encC4;
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <returns>The size of the key</returns>
        public int GetKeySize(IAsymmetricKey AsmKey)
        {
            if (AsmKey is MPKCPublicKey)
                return ((MPKCPublicKey)AsmKey).N;
            if (AsmKey is MPKCPrivateKey)
                return ((MPKCPrivateKey)AsmKey).N;

            throw new CryptoAsymmetricException("KobaraImaiCipher:Encrypt", "Unsupported Key type!", new ArgumentException());
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="MPKCPublicKey"/> for encryption, or a <see cref="MPKCPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the McEliece public or private key</param>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is MPKCPublicKey) && !(AsmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("KobaraImaiCipher:Initialize", "The key is not a valid McEliece key!", new InvalidDataException());

            m_isEncryption = (AsmKey is MPKCPublicKey);

            m_asmKey = AsmKey;

            if (m_isEncryption)
            {
                m_rndEngine = GetPrng(m_cprParams.RandomEngine);
                m_N = ((MPKCPublicKey)AsmKey).N;
                m_K = ((MPKCPublicKey)AsmKey).K;
                m_T = ((MPKCPublicKey)AsmKey).T;
                m_maxPlainText = (((MPKCPublicKey)AsmKey).K >> 3);
            }
            else
            {
                m_N = ((MPKCPrivateKey)AsmKey).N;
                m_K = ((MPKCPrivateKey)AsmKey).K;
                m_T = ((MPKCPrivateKey)AsmKey).T;
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="DigestType">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoAsymmetricException("KobaraImaiCipher:GetDigest", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="PrngType">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs PrngType)
        {
            try
            {
                return PrngFromName.GetInstance(PrngType);
            }
            catch
            {
                throw new CryptoAsymmetricException("KobaraImaiCipher:GetPrng", "The Prng type is not supported!", new ArgumentException());
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
                    if (m_dgtEngine != null)
                    {
                        m_dgtEngine.Dispose();
                        m_dgtEngine = null;
                    }
                    if (m_rndEngine != null)
                    {
                        m_rndEngine.Dispose();
                        m_rndEngine = null;
                    }
                    m_K = 0;
                    m_N = 0;
                    m_T = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
