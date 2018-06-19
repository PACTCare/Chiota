#region Directives
using System;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// NTRU Encrypt in C# (NTRUSharp)
// Copyright (C) 2015 John Underhill
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
//
// Based on the java project NTRUEncrypt by Tim Buktu: <https://github.com/tbuktu/ntru> and the C version
// <https://github.com/NTRUOpenSourceProject/ntru-crypto> NTRUOpenSourceProject/ntru-crypto.
// NTRU is owned and patented by Security Innovations: <https://www.securityinnovation.com/products/encryption-libraries/ntru-crypto/>,
// authors and originators include; Jeffrey Hoffstein, Jill Pipher, and Joseph H. Silverman.
// 
// Implementation Details:
// An implementation of NTRU Encrypt in C#.
// Written by John Underhill, April 09, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU
{
    /// <summary>
    /// This class implements the key pair generation of the NTRU Public Key Crypto System
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of generating a key pair:</description>
    /// <code>
    /// // use a predefined parameters set
    /// NtruParameters ps = DefinedParameters.EES1087EP3;
    /// 
    /// using (NTRUKeyGenerator gen = new NTRUKeyGenerator(ps))
    /// {
    ///     // generate a keypair
    ///     NtruKeyPair kp = gen.GenerateKeyPair();
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.NTRUKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.NTRUPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.NTRUPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.NTRUParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricCipher"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>Key Generation:</description>
    /// <list type="table">
    /// <item><description>Randomly generate polynomials f and g in Df, Dg respectively.</description></item>
    /// <item><description>Invert f in Rq to obtain fq, invert f in Rp to obtain fp, and check that g is invertible in Rq.</description></item>
    /// <item><description>The public key h = p ∗ g ∗ fq (mod q). The private key is the pair (f, fp).</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NTRU: A Ring Based <a href="http://binary.cr.yp.to/mcbits-20130616.pdf">Public Key Crypto System</a></description></item>
    /// <item><description><a href="https://www.securityinnovation.com/uploads/Crypto/TECH_ARTICLE_OPT.pdf">Optimizations</a> for NTRU</description></item>
    /// <item><description>Adaptive <a href="https://eprint.iacr.org/2015/127.pdf">Key Recovery Attacks</a> on NTRU-based Somewhat Homomorphic Encryption Schemes: </description></item>
    /// <item><description>Efficient Embedded Security Standards: <a href="http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf">EESS</a></description></item>
    /// <item><description><a href="https://www.securityinnovation.com/uploads/Crypto/lll25.pdf">Practical lattice-based cryptography</a>: NTRUEncrypt and NTRUSign: </description></item>
    /// <item><description>NTRU Cryptosystems <a href="https://www.securityinnovation.com/uploads/Crypto/NTRUTech016.pdf">Technical Report</a></description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent java project NTRU Encrypt by Tim Buktu: <a href="https://github.com/tbuktu/ntru/description">Release 1.2</a>, and
    /// the NTRUOpenSourceProject/ntru-crypto project provided by Security Innovation, Inc: <a href="https://github.com/NTRUOpenSourceProject/ntru-crypto">Release 1.</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class NTRUKeyGenerator : IAsymmetricGenerator
    {
        #region Constants
        private const string ALG_NAME = "NTRUKeyGenerator";
        #endregion

        #region Fields
        private readonly NTRUParameters m_ntruParams;
        private bool m_isDisposed;
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
        /// Constructs a new instance with a set of encryption parameters
        /// </summary>
        /// 
        /// <param name="CipherParams">Encryption parameters</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if a Prng that requires pre-initialization is specified; (wrong constructor)</exception>
        public NTRUKeyGenerator(NTRUParameters CipherParams, bool Parallel = true)
        {
            if (CipherParams.RandomEngine == Prngs.PBPrng)
                throw new CryptoAsymmetricException("MPKCKeyGenerator:Ctor", "Passphrase based digest and CTR generators must be pre-initialized, use the other constructor!", new ArgumentException());

          this.m_frcLinear = ParallelUtils.ForceLinear;
            ParallelUtils.ForceLinear = !Parallel;
          this.m_ntruParams = CipherParams;
          this.m_rndEngine = this.GetPrng(this.m_ntruParams.RandomEngine);
        }

        /// <summary>
        /// Use an initialized prng to generate the key; use this constructor with an Rng that requires pre-initialization, i.e. PBPrng
        /// </summary>
        /// 
        /// <param name="CipherParams">The NTRUParameters instance containing the cipher settings</param>
        /// <param name="RngEngine">An initialized Prng instance</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        public NTRUKeyGenerator(NTRUParameters CipherParams, IRandom RngEngine, bool Parallel = true)
        {
          this.m_frcLinear = ParallelUtils.ForceLinear;
            // passphrase gens must be linear processed
            if (RngEngine.GetType().Equals(typeof(PBPRng)))
                ParallelUtils.ForceLinear = true;
            else
                ParallelUtils.ForceLinear = !Parallel;

          this.m_ntruParams = CipherParams;
            // set source of randomness
          this.m_rndEngine = RngEngine;
        }

        private NTRUKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUKeyGenerator()
        {
          this.Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generates a new encryption key pair
        /// </summary>
        /// 
        /// <returns>A key pair</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            return this.GenerateKeyPair(this.m_rndEngine);
        }

        /// <summary>
        /// Generates an encryption key pair using a passphrase based prng.
        /// <para>Invoking this method with the same passphrase and salt will always return the same key pair.</para>
        /// </summary>
        /// <param name="Passphrase">The passphrase</param>
        /// <param name="Salt">Salt for the passphrase; can be <c>null</c> but this is strongly discouraged</param>
        /// <returns>A populated IAsymmetricKeyPair</returns>
        public IAsymmetricKeyPair GenerateKeyPair(byte[] Passphrase, byte[] Salt)
        {
            using (var dgt = this.GetDigest(this.m_ntruParams.Digest))
            {
              // Changes 10000 to 100 and false to true
                using (IRandom rnd = new PBPRng(dgt, Passphrase, Salt, 100, true))
                {
                    IRandom rng2 = ((PBPRng)rnd).CreateBranch(dgt);
                    return this.GenerateKeyPair(rnd, rng2);
                }
            }
        }

        /// <summary>
        /// A convenience method that generates a random salt vector for key pair generation.
        /// </summary>
        /// 
        /// <param name="Size">Byte length of the new salt</param>
        /// 
        /// <returns>A new salt vector</returns>
        public byte[] GenerateSalt(int Size = 16)
        {
            using (var rnd = new SecureRandom())
                return rnd.GetBytes(Size);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Generates a new encryption key pair
        /// </summary>
        /// 
        /// <param name="RngEngine">The random number generator to use for generating the secret polynomials f and g</param>
        /// 
        /// <returns>A key pair</returns>
        private IAsymmetricKeyPair GenerateKeyPair(IRandom RngEngine)
        {
            return this.GenerateKeyPair(RngEngine, RngEngine);
        }
        
        /// <summary>
        /// Generates a new encryption key pair
        /// </summary>
        /// 
        /// <param name="RngF">The random number generator to use for generating the secret polynomial f</param>
        /// <param name="RngG">The random number generator to use for generating the secret polynomial g</param>
        /// 
        /// <returns>A key pair</returns>
        private IAsymmetricKeyPair GenerateKeyPair(IRandom RngF, IRandom RngG)
        {
            var N = this.m_ntruParams.N;
            var q = this.m_ntruParams.Q;
            var fastFp = this.m_ntruParams.FastFp;
            var sparse = this.m_ntruParams.Sparse;
            var polyType = this.m_ntruParams.PolyType;
            IPolynomial t = null;
            IntegerPolynomial fq = null;
            IntegerPolynomial fp = null;
            IntegerPolynomial g = null;

            if (ParallelUtils.IsParallel)
            {
                var gA = new Action[] {
                    new Action(()=> g = this.GenerateG(RngG)), 
                    new Action(()=> this.GenerateFQ(RngF, out t, out fq, out fp))
                };
                Parallel.Invoke(gA);
            }
            else
            {
                // Choose a random g that is invertible mod q. 
                g = this.GenerateG(RngG);
                // choose a random f that is invertible mod 3 and q
              this.GenerateFQ(RngF, out t, out fq, out fp);
            }

            // if fastFp=true, fp=1
            if (fastFp)
            {
                fp = new IntegerPolynomial(N);
                fp.Coeffs[0] = 1;
            }

            var h = g.Multiply(fq, q);
            h.Mult3(q);
            h.EnsurePositive(q);

            var priv = new NTRUPrivateKey(t, fp, N, q, sparse, fastFp, polyType);
            var pub = new NTRUPublicKey(h, N, q);

            return new NTRUKeyPair(pub, priv);
        }

        private void GenerateFQ(IRandom Rng, out IPolynomial T, out IntegerPolynomial Fq, out IntegerPolynomial Fp)
        {
            var N = this.m_ntruParams.N;
            var q = this.m_ntruParams.Q;
            var df = this.m_ntruParams.DF;
            var df1 = this.m_ntruParams.DF1;
            var df2 = this.m_ntruParams.DF2;
            var df3 = this.m_ntruParams.DF3;
            var fastFp = this.m_ntruParams.FastFp;
            var sparse = this.m_ntruParams.Sparse;
            var polyType = this.m_ntruParams.PolyType;
            Fp = null;

            // choose a random f that is invertible mod 3 and q
            while (true)
            {
                IntegerPolynomial f;

                // choose random t, calculate f and fp
                if (fastFp)
                {
                    // if fastFp=true, f is always invertible mod 3
                    if (polyType == TernaryPolynomialType.SIMPLE)
                        T = PolynomialGenerator.GenerateRandomTernary(N, df, df, sparse, Rng);
                    else
                        T = ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3, Rng);

                    f = T.ToIntegerPolynomial();
                    f.Multiply(3);
                    f.Coeffs[0] += 1;
                }
                else
                {
                    if (polyType == TernaryPolynomialType.SIMPLE)
                        T = PolynomialGenerator.GenerateRandomTernary(N, df, df - 1, sparse, Rng);
                    else
                        T = ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3 - 1, Rng);

                    f = T.ToIntegerPolynomial();
                    Fp = f.InvertF3();

                    if (Fp == null)
                        continue;
                }

                Fq = f.InvertFq(q);

                if (Fq != null)
                    break;
            }
        }

        /// <remarks>
        /// Generates the ephemeral secret polynomial 'g'.
        /// </remarks>
        private IntegerPolynomial GenerateG(IRandom RngEngine)
        {
            var N = this.m_ntruParams.N;
            var dg = this.m_ntruParams.Dg;

            while (true)
            {
                var g = DenseTernaryPolynomial.GenerateRandom(N, dg, dg - 1, RngEngine);

                if (g.IsInvertiblePow2())
                    return g;
            }
        }

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
                throw new CryptoAsymmetricException("NTRUKeyGenerator:GetDigest", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the Prng
        /// </summary>
        /// 
        /// <param name="PrngType">Prng type</param>
        /// 
        /// <returns>Instance of Prng</returns>
        private IRandom GetPrng(Prngs PrngType)
        {
            try
            {
                return PrngFromName.GetInstance(PrngType);
            }
            catch
            {
                throw new CryptoAsymmetricException("NTRUKeyGenerator:GetPrng", "The Prng type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            ParallelUtils.ForceLinear = this.m_frcLinear;
          this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!this.m_isDisposed && Disposing)
            {
                try
                {
                    if (this.m_rndEngine != null)
                    {
                      this.m_rndEngine.Dispose();
                      this.m_rndEngine = null;
                    }
                }
                catch { }

              this.m_isDisposed = true;
            }
        }
        #endregion
    }
}
