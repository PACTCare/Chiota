#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// This class implements the Fujisaki/Okamoto conversion of the McEliecePKCS
    /// </summary>
    /// <remarks>
    /// <para>Fujisaki and Okamoto propose hybrid encryption that merges a symmetric encryption scheme which is secure in the find-guess model with 
    /// an asymmetric one-way encryption scheme which is sufficiently probabilistic to obtain a public key cryptosystem which is CCA2-secure. 
    /// For details, see D. Engelbert, R. Overbeck, A. Schmidt, "A summary of the development of the McEliece Cryptosystem", technical report.</para>
    /// </remarks>
    internal class FujisakiCipher : IMPKCCiphers, IDisposable
    {
        #region Constants
        /// <summary>
        /// The OID of the algorithm
        /// </summary>
        public static readonly byte[] OID = System.Text.Encoding.ASCII.GetBytes("1.3.6.1.4.1.8301.3.1.3.4.2.1");
        #endregion

        #region Fields
        private IAsymmetricKey m_asmKey;
        private MPKCParameters m_cprParams;
        private IDigest m_dgtEngine;
        private bool m_isDisposed = false;
        private bool m_isEncryption;
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
        /// <param name="Paramaters">The cipher parameters</param>
        public FujisakiCipher(MPKCParameters Paramaters)
        {
            m_cprParams = Paramaters;
            m_dgtEngine = GetDigest(Paramaters.Digest);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~FujisakiCipher()
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
                throw new CryptoAsymmetricException("FujisakiCipher:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            int c1Len = (m_N + 7) >> 3;
            int c2Len = Input.Length - c1Len;

            // split ciphertext (c1||c2)
            byte[][] c1c2 = ByteUtils.Split(Input, c1Len);
            byte[] c1 = c1c2[0];
            byte[] c2 = c1c2[1];

            // decrypt c1 ...
            GF2Vector hrmVec = GF2Vector.OS2VP(m_N, c1);
            GF2Vector[] decC1 = CCA2Primitives.Decrypt((MPKCPrivateKey)m_asmKey, hrmVec);
            byte[] rBytes = decC1[0].GetEncoded();
            // ... and obtain error vector z
            GF2Vector z = decC1[1];

            byte[] mBytes;
            // get PRNG object..
            using (KDF2 sr0 = new KDF2(GetDigest(m_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rBytes);
                // generate random sequence
                mBytes = new byte[c2Len];
                sr0.Generate(mBytes);
            }

            // XOR with c2 to obtain m
            for (int i = 0; i < c2Len; i++)
                mBytes[i] ^= c2[i];

            // compute H(r||m)
            byte[] rmBytes = ByteUtils.Concatenate(rBytes, mBytes);
            byte[] hrm = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.BlockUpdate(rmBytes, 0, rmBytes.Length);
            m_dgtEngine.DoFinal(hrm, 0);
            // compute Conv(H(r||m))
            hrmVec = CCA2Conversions.Encode(m_N, m_T, hrm);

            // check that Conv(H(m||r)) = z
            if (!hrmVec.Equals(z))
                throw new CryptoAsymmetricException("FujisakiCipher:Decrypt", "Bad Padding: invalid ciphertext!", new InvalidDataException());

            // return plaintext m
            return mBytes;
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
                throw new CryptoAsymmetricException("FujisakiCipher:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            // generate random vector r of length k bits
            GF2Vector r = new GF2Vector(m_K, m_rndEngine);
            // convert r to byte array
            byte[] rBytes = r.GetEncoded();
            // compute (r||input)
            byte[] rm = ByteUtils.Concatenate(rBytes, Input);

            // compute H(r||input)
            m_dgtEngine.BlockUpdate(rm, 0, rm.Length);
            byte[] hrm = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hrm, 0);
            // convert H(r||input) to error vector z
            GF2Vector z = CCA2Conversions.Encode(m_N, m_T, hrm);

            // compute c1 = E(r, z)
            byte[] c1 = CCA2Primitives.Encrypt((MPKCPublicKey)m_asmKey, r, z).GetEncoded();
            byte[] c2;

            // get PRNG object
            using (KDF2 sr0 = new KDF2(GetDigest(m_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rBytes);
                // generate random c2
                c2 = new byte[Input.Length];
                sr0.Generate(c2);
            }

            // XOR with input
            for (int i = 0; i < Input.Length; i++)
                c2[i] ^= Input[i];

            // return (c1||c2)
            return ByteUtils.Concatenate(c1, c2);
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

            throw new CryptoAsymmetricException("FujisakiCipher:Encrypt", "Unsupported Key type!", new ArgumentException());
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
                throw new CryptoAsymmetricException("FujisakiCipher:Initialize", "The key is not a valid McEliece key!", new InvalidDataException());

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
                throw new CryptoAsymmetricException("FujisakiCipher:GetDigest", "The digest type is not supported!", new ArgumentException());
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
                throw new CryptoAsymmetricException("FujisakiCipher:GetPrng", "The Prng type is not supported!", new ArgumentException());
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
