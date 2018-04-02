#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
using System.Collections.Generic;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Exceptions;
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

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU
{
    /// <summary>
    /// Generates the Public and Private key pair.
    /// <para>The parameter "p" is hardcoded to 3.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of generating a key pair:</description>
    /// <code>
    /// // use a predefined parameters
    /// NtruParameters param = DefinedParameters.EES1087EP3;
    /// 
    /// using (NTRUKeyGenerator kg = new NTRUKeyGenerator(param))
    /// {
    ///     // generate a keypair
    ///     NtruKeyPair kp = kg.GenerateKeyPair();
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.0.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.NTRUKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU NTRUKeyPair Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.NTRUPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU NTRUPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.NTRUPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU NTRUPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.NTRUParameters">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU NTRUParameters Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricCipher">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricCipher Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prngs">VTDev.Libraries.CEXEngine.Crypto.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h5>Key Generation:</h5></description>
    /// <list type="table">
    /// <item><description>Randomly generate polynomials f and g in Df , Dg respectively.</description></item>
    /// <item><description>Invert f in Rq to obtain fq, invert f in Rp to obtain fp, and check that g is invertible in Rq.</description></item>
    /// <item><description>The public key h = p ∗ g ∗ fq (mod q). The private key is the pair (f, fp).</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NTRU: A Ring Based Public Key Crypto System<cite>NTRU Crypto</cite>.</description></item>
    /// <item><description>Optimizations for NTRU<cite>NTRU Optimizations</cite>.</description></item>
    /// <item><description>Adaptive Key Recovery Attacks on NTRU-based Somewhat Homomorphic Encryption Schemes<cite>NTRU Adaptive</cite>.</description></item>
    /// <item><description>Efficient Embedded Security Standards (EESS)<cite>NTRU EESS</cite>.</description></item>
    /// <item><description>Practical lattice-based cryptography: NTRUEncrypt and NTRUSign<cite>NTRU Practical</cite>.</description></item>
    /// <item><description>NTRU Cryptosystems Technical Report<cite>NTRU Technical</cite>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent java project NTRU Encrypt by Tim Buktu: <see href="https://github.com/tbuktu/ntru/description">Release 1.2</see>, and
    /// the NTRUOpenSourceProject/ntru-crypto project provided by Security Innovation, Inc: <see href="https://github.com/NTRUOpenSourceProject/ntru-crypto">Release 1.2</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class NTRUKeyGenerator : IAsymmetricGenerator
    {
        #region Fields
        private IDigest _dgtEngine;
        private readonly NTRUParameters _encParams;
        private bool _isDisposed;
        private IRandom _rngEngine;
        private bool _isParallel = true;
        #endregion
        
        #region Constructor
        /// <summary>
        /// Constructs a new instance with a set of encryption parameters
        /// </summary>
        /// 
        /// <param name="CipherParams">Encryption parameters</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        public NTRUKeyGenerator(NTRUParameters CipherParams, bool Parallel = true)
        {
            if (CipherParams.RandomEngine != Prngs.CTRPrng || CipherParams.RandomEngine != Prngs.CSPRng)
                _isParallel = false;
            else
                _isParallel = Parallel;

            _encParams = CipherParams;
            _dgtEngine = GetDigest(_encParams.MessageDigest);
            _rngEngine = GetPrng(_encParams.RandomEngine);
        }

        private NTRUKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUKeyGenerator()
        {
            Dispose(false);
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
            return GenerateKeyPair(_rngEngine);
        }

        /// <summary>
        /// Generates an encryption key pair using a passphrase based drbg.
        /// <para>Invoking this method with the same passphrase and salt will always return the same key pair.</para>
        /// </summary>
        /// 
        /// <param name="Passphrase">The passphrase</param>
        /// <param name="Salt">Salt for the passphrase; can be <c>null</c> but this is strongly discouraged</param>
        /// 
        /// <returns>A populated IAsymmetricKeyPair</returns>
        public IAsymmetricKeyPair GenerateKeyPair(byte[] Passphrase, byte[] Salt)
        {
            _dgtEngine.Reset();

            using (IRandom rnd = new PBPRng(_dgtEngine, Passphrase, Salt, 10000, false))
            {
                IRandom rng2 = ((PBPRng)rnd).CreateBranch(_dgtEngine);
                return GenerateKeyPair(rnd, rng2);
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
            using (SecureRandom rnd = new SecureRandom())
                return rnd.GetBytes(Size);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Generates a new encryption key pair
        /// </summary>
        /// 
        /// <param name="Rng">The random number generator to use for generating the secret polynomials f and g</param>
        /// 
        /// <returns>A key pair</returns>
        private IAsymmetricKeyPair GenerateKeyPair(IRandom Rng)
        {
            return GenerateKeyPair(Rng, Rng);
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
            int N = _encParams.N;
            int q = _encParams.Q;
            bool fastFp = _encParams.FastFp;
            bool sparse = _encParams.Sparse;
            TernaryPolynomialType polyType = _encParams.PolyType;
            IPolynomial t = null;
            IntegerPolynomial fq = null;
            IntegerPolynomial fp = null;
            IntegerPolynomial g = null;

            if (ParallelUtils.IsParallel && _isParallel)
            {
                Action[] gA = new Action[] {
                    new Action(()=> g = GenerateG(RngG)), 
                    new Action(()=> GenerateFQ(RngF, out t, out fq, out fp))
                };
                Parallel.Invoke(gA);
            }
            else
            {
                // Choose a random g that is invertible mod q. 
                g = GenerateG(RngG);
                // choose a random f that is invertible mod 3 and q
                GenerateFQ(RngF, out t, out fq, out fp);
            }

            // if fastFp=true, fp=1
            if (fastFp)
            {
                fp = new IntegerPolynomial(N);
                fp.Coeffs[0] = 1;
            }

            IntegerPolynomial h = g.Multiply(fq, q);
            h.Mult3(q);
            h.EnsurePositive(q);

            NTRUPrivateKey priv = new NTRUPrivateKey(t, fp, N, q, sparse, fastFp, polyType);
            NTRUPublicKey pub = new NTRUPublicKey(h, N, q);

            return new NTRUKeyPair(pub, priv);
        }

        private void GenerateFQ(IRandom Rng, out IPolynomial t, out IntegerPolynomial fq, out IntegerPolynomial fp)
        {
            int N = _encParams.N;
            int q = _encParams.Q;
            int df = _encParams.DF;
            int df1 = _encParams.DF1;
            int df2 = _encParams.DF2;
            int df3 = _encParams.DF3;
            bool fastFp = _encParams.FastFp;
            bool sparse = _encParams.Sparse;
            TernaryPolynomialType polyType = _encParams.PolyType;
            fp = null;

            // choose a random f that is invertible mod 3 and q
            while (true)
            {
                IntegerPolynomial f;

                // choose random t, calculate f and fp
                if (fastFp)
                {
                    // if fastFp=true, f is always invertible mod 3
                    if (polyType == TernaryPolynomialType.SIMPLE)
                        t = PolynomialGenerator.GenerateRandomTernary(N, df, df, sparse, Rng);
                    else
                        t = ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3, Rng);

                    f = t.ToIntegerPolynomial();
                    f.Multiply(3);
                    f.Coeffs[0] += 1;
                }
                else
                {
                    if (polyType == TernaryPolynomialType.SIMPLE)
                        t = PolynomialGenerator.GenerateRandomTernary(N, df, df - 1, sparse, Rng);
                    else
                        t = ProductFormPolynomial.GenerateRandom(N, df1, df2, df3, df3 - 1, Rng);

                    f = t.ToIntegerPolynomial();
                    fp = f.InvertF3();

                    if (fp == null)
                        continue;
                }

                fq = f.InvertFq(q);

                if (fq != null)
                    break;
            }
        }

        /// <remarks>
        /// Generates the ephemeral secret polynomial 'g'.
        /// </remarks>
        private IntegerPolynomial GenerateG(IRandom Rng)
        {
            int N = _encParams.N;
            int dg = _encParams.Dg;

            while (true)
            {
                DenseTernaryPolynomial g = DenseTernaryPolynomial.GenerateRandom(N, dg, dg - 1, Rng);

                if (g.IsInvertiblePow2())
                    return g;
            }
        }

        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="Digest">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests Digest)
        {
            switch (Digest)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.Keccak1024:
                    return new Keccak1024();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                case Digests.Skein1024:
                    return new Skein1024();
                default:
                    throw new NTRUException("NTRUKeyGenerator:GetDigest", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the Prng
        /// </summary>
        /// 
        /// <param name="Prng">Prng type</param>
        /// 
        /// <returns>Instance of Prng</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPRng:
                    return new CSPRng();
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
                    throw new NTRUException("NTRUKeyGenerator:GetDigest", "The Prng type is not supported!", new ArgumentException());
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_dgtEngine != null)
                    {
                        _dgtEngine.Dispose();
                        _dgtEngine = null;
                    }
                    if (_rngEngine != null)
                    {
                        _rngEngine.Dispose();
                        _rngEngine = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
