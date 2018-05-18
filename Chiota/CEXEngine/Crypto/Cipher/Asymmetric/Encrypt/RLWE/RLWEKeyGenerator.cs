#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
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
    /// This class implements key pair generation of the Ring-LWE Public Key Cryptosystem
    /// </summary>
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// RLWEParameters ps = RLWEParamSets.RLWEN512Q12289;
    /// RLWEKeyGenerator gen = new RLWEKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEEncrypt"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
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
    public sealed class RLWEKeyGenerator : IAsymmetricGenerator
    {
        #region Constants
        private const string ALG_NAME = "RLWEKeyGenerator";
        #endregion

        #region Fields
        private bool m_isDisposed;
        private RLWEParameters m_rlweParams;
        private IRandom m_rndEngine;
        private bool m_frcLinear = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The RLWEParameters instance containing the cipher settings</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if a Prng that requires pre-initialization is specified; (wrong constructor)</exception>
        public RLWEKeyGenerator(RLWEParameters CipherParams, bool Parallel = true)
        {
            if (CipherParams.RandomEngine == Prngs.PBPrng)
                throw new CryptoAsymmetricException("RLWEKeyGenerator:Ctor", "Passphrase based digest and CTR generators must be pre-initialized, use the other constructor!", new ArgumentException());

            m_frcLinear = ParallelUtils.ForceLinear;
            ParallelUtils.ForceLinear = !Parallel;
            m_rlweParams = CipherParams;
            m_rndEngine = GetPrng(CipherParams.RandomEngine);
        }

        /// <summary>
        /// Use an initialized prng to generate the key; use this constructor with an Rng that requires pre-initialization, i.e. PBPrng
        /// </summary>
        /// 
        /// <param name="CipherParams">The RLWEParameters instance containing the cipher settings</param>
        /// <param name="RngEngine">An initialized Prng instance</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        public RLWEKeyGenerator(RLWEParameters CipherParams, IRandom RngEngine, bool Parallel = true)
        {
            m_rlweParams = CipherParams;
            m_rndEngine = RngEngine;
            m_frcLinear = ParallelUtils.ForceLinear;

            // passphrase gens must be linear processed
            if (RngEngine.GetType().Equals(typeof(PBPRng)))
                ParallelUtils.ForceLinear = true;
            else
                ParallelUtils.ForceLinear = !Parallel;
        }

        private RLWEKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEKeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A RLWEKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            if (m_rlweParams.N == 512)
                return new NTT512(m_rndEngine).Generate();
            else
                return new NTT256(m_rndEngine).Generate();
        }

        /// <summary>
        /// Generates an encryption key pair using a passphrase based prng.
        /// <para>Invoking this method with the same passphrase and salt will always return the same key pair.</para>
        /// </summary>
        /// 
        /// <param name="Passphrase">The passphrase</param>
        /// <param name="Salt">Salt for the passphrase; can be <c>null</c> but this is strongly discouraged</param>
        /// 
        /// <returns>A populated IAsymmetricKeyPair</returns>
        public IAsymmetricKeyPair GenerateKeyPair(byte[] Passphrase, byte[] Salt)
        {
            using (IDigest dgt = GetDigest(m_rlweParams.Digest))
            {
                using (IRandom rnd = new PBPRng(dgt, Passphrase, Salt, 10000, false))
                    return GenerateKeyPair();
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
                throw new CryptoRandomException("RLWEKeyGenerator:GetDigest", "The digest type is not recognized!", new ArgumentException());
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
                throw new CryptoAsymmetricException("RLWEKeyGenerator:GetPrng", "The Prng type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            ParallelUtils.ForceLinear = m_frcLinear;
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
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
