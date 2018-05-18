#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// The Ring-LWE Asymmetric Cipher
// 
// Implementation Details:
// An implementation based on the description in the paper 'Efficient Software Implementation of Ring-LWE Encryption' 
// https://eprint.iacr.org/2014/725.pdf and accompanying Github project: https://github.com/ruandc/Ring-LWE-Encryption
// Written by John Underhill, June 8, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE
{
    /// <summary>
    /// An Ring-LWE cipher implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting an array:</description>
    /// <code>
    /// RLWEParameters encParams = new RLWEParameters(512, 12289, 12.18, new byte[] { 2, 5, 1 }))
    /// RLWEKeyGenerator keyGen = new RLWEKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// 
    /// byte[] data = new byte[64];
    /// byte[] enc, dec;
    /// 
    /// // encrypt an array
    /// using (RLWEEncrypt cipher = new RLWEEncrypt(encParams))
    /// {
    ///     cipher.Initialize(keyPair.PublicKey);
    ///     enc = cipher.Encrypt(data);
    /// }
    /// 
    /// // decrypt the cipher text
    /// using (RLWEEncrypt cipher = new RLWEEncrypt(encParams))
    /// {
    ///     cipher.Initialize(keyPair.PrivateKey);
    ///     dec = cipher.Decrypt(enc);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Efficient Software Implementation of <a href="https://eprint.iacr.org/2014/725.pdf">Ring-LWE Encryption</a></description></item>
    /// <item><description>Compact Ring-LWE <a href="http://www.cosic.esat.kuleuven.be/publications/article-2444.pdf">Cryptoprocessor</a></description></item>
    /// <item><description>A Simple <a href="http://eprint.iacr.org/2012/688.pdf">Provably Secure Key Exchange</a> Scheme Based on the Learning with Errors Problem</description></item>
    /// <item><description>The <a href="http://www.egr.unlv.edu/~bein/pubs/knuthyaotalg.pdf">Knuth-Yao Quadrangle-Inequality Speedup</a> is a Consequence of Total-Monotonicity</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Ring-LWE-Encryption C version: <a href="https://github.com/ruandc/Ring-LWE-Encryption">ruandc/Ring-LWE-Encryption</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class RLWEEncrypt : IAsymmetricCipher
    {
        #region Constants
        private const string ALG_NAME = "RLWEEncrypt";
        #endregion

        #region Fields
        private IAsymmetricKey m_asmKey;
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        private bool m_isEncryption = false;
        private int m_maxPlainText;
        private IRandom m_rndEngine;
        private int m_N;
        private int m_Q;
        private double m_Sigma;
        private int m_mFp;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The cipher is initialized for encryption
        /// </summary>
        public bool IsEncryption
        {
            get
            {
                if (!m_isInitialized)
                    throw new CryptoAsymmetricException("RLWEEncrypt:IsEncryption", "The cipher must be initialized before state can be determined!", new InvalidOperationException());

                return m_isEncryption;
            }
        }

        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized</exception>
        public int MaxPlainText
        {
            get 
            {
                if (m_maxPlainText == 0 || !m_isInitialized)
                    throw new CryptoAsymmetricException("RLWEEncrypt:MaxPlainText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return m_maxPlainText; 
            }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class; Prng is created automatically
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher engine</param>
        public RLWEEncrypt(RLWEParameters CipherParams)
        {
            m_rndEngine = GetPrng(CipherParams.RandomEngine);
            m_N = CipherParams.N;
            m_Q = CipherParams.Q;
            m_Sigma = CipherParams.Sigma;
            m_mFp = CipherParams.MFP;

            if (CipherParams.N == 256)
                m_maxPlainText = 32;
            else
                m_maxPlainText = 64;
        }

        /// <summary>
        /// Initialize this class with an initialized Prng
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher parameters</param>
        /// <param name="Engine">The initialized cipher prng</param>
        public RLWEEncrypt(RLWEParameters CipherParams, IRandom Engine)
        {
            m_rndEngine = Engine;
        }

        private RLWEEncrypt()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEEncrypt()
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
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized</exception>
        public byte[] Decrypt(byte[] Input)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWEEncrypt:Decrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (m_isEncryption)
                throw new CryptoAsymmetricException("RLWEEncrypt:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            int plen = m_N >> 3;

            if (m_N == 512)
            {
                NTT512 ntt = new NTT512(m_rndEngine);
                return ntt.Decrypt((RLWEPrivateKey)m_asmKey, Input).SubArray(m_mFp, plen - m_mFp);
            }
            else
            {
                NTT256 ntt = new NTT256(m_rndEngine);
                return ntt.Decrypt((RLWEPrivateKey)m_asmKey, Input).SubArray(m_mFp, plen - m_mFp);
            }
        }

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized, or input text is too long</exception>
        public byte[] Encrypt(byte[] Input)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWEEncrypt:Encrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (Input.Length > m_maxPlainText - m_mFp)
                throw new CryptoAsymmetricException("RLWEEncrypt:Encrypt", "The input text is too long!", new ArgumentOutOfRangeException());
            if (!m_isEncryption)
                throw new CryptoAsymmetricException("RLWEEncrypt:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            int plen = m_N >> 3;

            if (m_N == 512)
            {
                NTT512 ntt = new NTT512(m_rndEngine);
                byte[] ptx = new byte[plen];

                if (Input.Length < m_maxPlainText)
                {
                    ptx = m_rndEngine.GetBytes(plen);
                    Array.Copy(Input, 0, ptx, m_mFp, Input.Length);
                }
                else
                {
                    Array.Copy(Input, 0, ptx, 0, Input.Length);
                }

                return ntt.Encrypt((RLWEPublicKey)m_asmKey, ptx);
            }
            else
            {
                NTT256 ntt = new NTT256(m_rndEngine);
                byte[] ptx = new byte[plen];

                if (Input.Length < m_maxPlainText)
                {
                    ptx = m_rndEngine.GetBytes(plen);
                    Array.Copy(Input, 0, ptx, m_mFp, Input.Length);
                }
                else
                {
                    Array.Copy(Input, 0, ptx, 0, Input.Length);
                }

                return ntt.Encrypt((RLWEPublicKey)m_asmKey, ptx);
            }
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <param name="AsmKey">The key</param>
        /// 
        /// <returns>The size of the key</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized, or key is invalid</exception>
        public int GetKeySize(IAsymmetricKey AsmKey)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWEEncrypt:GetKeySize", "The cipher has not been initialized!", new InvalidOperationException());

            if (AsmKey is RLWEPublicKey)
                return ((RLWEPublicKey)AsmKey).N;
            if (AsmKey is RLWEPrivateKey)
                return ((RLWEPrivateKey)AsmKey).N;

            throw new CryptoAsymmetricException("RLWEEncrypt:GetKeySize", "Unsupported key type!", new InvalidDataException());
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="RLWEPublicKey"/> for encryption, or a <see cref="RLWEPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the Ring-LWE Public or Private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is RLWEPublicKey) && !(AsmKey is RLWEPrivateKey))
                throw new CryptoAsymmetricException("RLWEEncrypt:Initialize", "The key is not a valid Ring-KWE key!", new InvalidDataException());

            m_isEncryption = (AsmKey is RLWEPublicKey);
            m_asmKey = AsmKey;
            m_isInitialized = true;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="Prng">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.SP20Prng:
                    return new SP20Prng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPPrng:
                    return new CSPPrng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new CryptoAsymmetricException("RLWEEncrypt:GetPrng", "The Prng type is not supported!", new ArgumentException());
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
                    if (m_rndEngine != null)
                    {
                        m_rndEngine.Dispose();
                        m_rndEngine = null;
                    }
                    m_maxPlainText = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
