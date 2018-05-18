#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// This class implements the Pointcheval conversion of the McEliecePKCS.
    /// <para>Pointcheval presents a generic technique to make a CCA2-secure cryptosystem 
    /// from any partially trapdoor one-way function in the random oracle model.</para>
    /// </summary>
    internal class PointchevalCipher : IMPKCCiphers, IDisposable
    {
        #region Constants
        /// <summary>
        /// The OID of the algorithm
        /// </summary>
        public static readonly byte[] OID = System.Text.Encoding.ASCII.GetBytes("1.3.6.1.4.1.8301.3.1.3.4.2.2");
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
        public PointchevalCipher(MPKCParameters Parameters)
        {
            m_cprParams = Parameters;
            m_dgtEngine = GetDigest(Parameters.Digest);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PointchevalCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        public byte[] Decrypt(byte[] Input)
        {
            if (m_isEncryption)
                throw new CryptoAsymmetricException("PointchevalCipher:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            int c1Len = (m_N + 7) >> 3;
            int c2Len = Input.Length - c1Len;
            // split cipher text (c1||c2)
            byte[][] c1c2 = ByteUtils.Split(Input, c1Len);
            byte[] c1 = c1c2[0];
            byte[] c2 = c1c2[1];

            // decrypt c1 ...
            GF2Vector c1Vec = GF2Vector.OS2VP(m_N, c1);
            GF2Vector[] c1Dec = CCA2Primitives.Decrypt((MPKCPrivateKey)m_asmKey, c1Vec);
            byte[] rPrimeBytes = c1Dec[0].GetEncoded();
            // ... and obtain error vector z
            GF2Vector z = c1Dec[1];

            byte[] mrBytes;
            // get PRNG object
            using (KDF2 sr0 = new KDF2(GetDigest(m_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rPrimeBytes);
                // generate random sequence
                mrBytes = new byte[c2Len];
                sr0.Generate(mrBytes);
            }

            // XOR with c2 to obtain (m||r)
            for (int i = 0; i < c2Len; i++)
                mrBytes[i] ^= c2[i];

            // compute H(m||r)
            m_dgtEngine.BlockUpdate(mrBytes, 0, mrBytes.Length);
            byte[] hmr = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hmr, 0);

            // compute Conv(H(m||r))
            c1Vec = CCA2Conversions.Encode(m_N, m_T, hmr);

            // check that Conv(H(m||r)) = z
            if (!c1Vec.Equals(z))
                throw new CryptoAsymmetricException("PointchevalCipher:Decrypt", "Bad Padding: Invalid ciphertext!", new ArgumentException());

            // split (m||r) to obtain m
            int kDiv8 = m_K >> 3;
            byte[][] mr = ByteUtils.Split(mrBytes, c2Len - kDiv8);

            // return plain text m
            return mr[0];
        }

        public byte[] Encrypt(byte[] Input)
        {
            if (!m_isEncryption)
                throw new CryptoAsymmetricException("PointchevalCipher:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            int kDiv8 = m_K >> 3;
            // generate random r of length k div 8 bytes
            byte[] r = new byte[kDiv8];
            m_rndEngine.GetBytes(r);
            // generate random vector r' of length k bits
            GF2Vector rPrime = new GF2Vector(m_K, m_rndEngine);
            // convert r' to byte array
            byte[] rPrimeBytes = rPrime.GetEncoded();
            // compute (input||r)
            byte[] mr = ByteUtils.Concatenate(Input, r);
            // compute H(input||r)
            m_dgtEngine.BlockUpdate(mr, 0, mr.Length);
            byte[] hmr = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hmr, 0);

            // convert H(input||r) to error vector z
            GF2Vector z = CCA2Conversions.Encode(m_N, m_T, hmr);

            // compute c1 = E(rPrime, z)
            byte[] c1 = CCA2Primitives.Encrypt((MPKCPublicKey)m_asmKey, rPrime, z).GetEncoded();
            byte[] c2;
            // get PRNG object
            using (KDF2 sr0 = new KDF2(GetDigest(m_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rPrimeBytes);
                // generate random c2
                c2 = new byte[Input.Length + kDiv8];
                sr0.Generate(c2);
            }

            // XOR with input
            for (int i = 0; i < Input.Length; i++)
                c2[i] ^= Input[i];

            // XOR with r
            for (int i = 0; i < kDiv8; i++)
                c2[Input.Length + i] ^= r[i];

            // return (c1||c2)
            return ByteUtils.Concatenate(c1, c2);
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <returns>The size of the key</returns>
        public int GetKeySize(IAsymmetricKey Key)
        {
            if (Key is MPKCPublicKey)
                return ((MPKCPublicKey)Key).N;
            if (Key is MPKCPrivateKey)
                return ((MPKCPrivateKey)Key).N;

            throw new CryptoAsymmetricException("PointchevalCipher:Encrypt", "Unsupported Key type!", new ArgumentException());
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
                throw new CryptoAsymmetricException("PointchevalCipher:Initialize", "The key is not a valid McEliece key!", new InvalidDataException());

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
                throw new CryptoAsymmetricException("PointchevalCipher:GetDigest", "The digest type is not supported!", new ArgumentException());
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
                throw new CryptoAsymmetricException("PointchevalCipher:GetPrng", "The Prng type is not supported!", new ArgumentException());
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
