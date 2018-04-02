#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Tools;
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

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU
{
    /// <summary>
    /// Encrypts and decrypts a message.
    /// <para>The parameter "p" is hardcoded to 3.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of encryption/decryption of plain text:</description>
    /// <code>
    /// // use a predefined parameters
    /// NtruParameters param = DefinedParameters.EES1087EP3;
    /// 
    /// using (NtruEncrypt ntru = new NtruEncrypt(param))
    /// {
    ///     // encrypt
    ///     byte[] encrypted = ntru.Encrypt(plaintext, kp.PublicKey);
    ///     // decrypt
    ///     byte[] decrypted = ntru.Decrypt(encrypted, kp);
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
    /// <description><h4>Basic Operations:</h4></description>
    /// 
    /// <description><h5>Encryption</h5></description>
    /// <list type="table">
    /// <item><description>Randomly select a “small” polynomial r ∈ Dr.</description></item>
    /// <item><description>Calculate the ciphertext e as e ≡ r ∗ h+m (mod q).</description></item>
    /// </list>
    /// 
    /// <description><h5>Decryption:</h5></description>
    /// <list type="table">
    /// <item><description>Calculate a ≡ center(f ∗ e), where the centering operation center reduces its input into the interval [A,A+q−1].</description></item>
    /// <item><description>Recover m by calculating m ≡ fp ∗ a (mod p).</description></item>
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
    public sealed class NTRUEncrypt : IAsymmetricCipher
    {
        #region Fields
        private IDigest _dgtEngine;
        private readonly NTRUParameters _encParams;
        private NTRUKeyPair _keyPair;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private IRandom _rndEngine;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        /// 
        /// <exception cref="NTRUException">Thrown if the cipher is not initialized</exception>
        public int MaxPlainText
        {
            get
            {
                if (_encParams == null)
                    throw new NTRUException("NTRUEncrypt:MaxCipherText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return _encParams.GetMaxMessageLength();
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a new instance with a set of encryption parameters
        /// </summary>
        /// 
        /// <param name="NtruParams">Encryption parameters</param>
        public NTRUEncrypt(NTRUParameters NtruParams)
        {
            _encParams = NtruParams;
            _dgtEngine = GetDigest(_encParams.MessageDigest);
            _rndEngine = GetPrng(_encParams.RandomEngine);
        }

        private NTRUEncrypt()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUEncrypt()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypts a message
        /// </summary>
        /// 
        /// <param name="Input">The message to decrypt</param>
        /// 
        /// <returns>The decrypted message</returns>
        /// 
        /// <exception cref="NTRUException">If not initialized, the specified hash algorithm is invalid, the encrypted data is invalid, or <c>MaxLenBytes</c> is greater than 255</exception>
        public byte[] Decrypt(byte[] Input)
        {
            if (!_isInitialized)
                throw new NTRUException("NTRUEncrypt:Decrypt", "The cipher has not been initialized!", new InvalidOperationException());

            IPolynomial priv_t = ((NTRUPrivateKey)_keyPair.PrivateKey).T;
            IntegerPolynomial priv_fp = ((NTRUPrivateKey)_keyPair.PrivateKey).FP;
            IntegerPolynomial pub = ((NTRUPublicKey)_keyPair.PublicKey).H;
            int N = _encParams.N;
            int q = _encParams.Q;
            int db = _encParams.Db;
            int maxMsgLenBytes = _encParams.MaxMsgLenBytes;
            int dm0 = _encParams.Dm0;
            int maxM1 = _encParams.MaxM1;
            int minCallsMask = _encParams.MinMGFHashCalls;
            bool hashSeed = _encParams.HashSeed;
            int bLen = db / 8;
            IntegerPolynomial e = IntegerPolynomial.FromBinary(Input, N, q);
            IntegerPolynomial ci = Decrypt(e, priv_t, priv_fp);

            if (ci.Count(-1) < dm0)
                throw new NTRUException("NTRUEncrypt:Decrypt", "Less than dm0 coefficients equal -1", new InvalidDataException());
            if (ci.Count(0) < dm0)
                throw new NTRUException("NTRUEncrypt:Decrypt", "Less than dm0 coefficients equal 0", new InvalidDataException());
            if (ci.Count(1) < dm0)
                throw new NTRUException("NTRUEncrypt:Decrypt", "Less than dm0 coefficients equal 1", new InvalidDataException());
            //if (maxMsgLenBytes > 255)
            //    throw new NTRUException("NTRUEncrypt:Decrypt", "maxMsgLenBytes values bigger than 255 are not supported", new ArgumentOutOfRangeException());

            IntegerPolynomial cR = e;
            cR.Subtract(ci);
            cR.ModPositive(q);

            byte[] coR4 = cR.ToBinary4();
            IntegerPolynomial mask = MGF(coR4, N, minCallsMask, hashSeed);
            IntegerPolynomial cMTrin = ci;
            cMTrin.Subtract(mask);
            cMTrin.Mod3();

            byte[] cb, p0, cm;
            using (BinaryReader reader = new BinaryReader(new MemoryStream(cMTrin.ToBinary3Sves(maxM1 > 0))))
            {
                cb = new byte[bLen];
                reader.Read(cb, 0, cb.Length);
                // llen=1, so read one byte
                int cl = reader.ReadByte() & 0xFF;

                if (cl > maxMsgLenBytes)
                    throw new NTRUException("NTRUEncrypt:Decrypt", string.Format("Message too long: {0} > {1}!", cl, maxMsgLenBytes), new InvalidDataException());

                cm = new byte[cl];
                reader.Read(cm, 0, cm.Length);
                p0 = new byte[reader.BaseStream.Length - reader.BaseStream.Position];
                reader.Read(p0, 0, p0.Length);
            }

            if (!Compare.AreEqual(p0, new byte[p0.Length]))
                throw new NTRUException("NTRUEncrypt:Decrypt", "The message is not followed by zeroes!", new InvalidDataException());

            byte[] sData = GetSeed(cm, pub, cb);
            IPolynomial cr = GenerateBlindingPoly(sData);
            IntegerPolynomial cRPrime = cr.Multiply(pub);
            cRPrime.ModPositive(q);

            if (!cRPrime.Equals(cR))
                throw new NTRUException("NTRUEncrypt:Decrypt", "Invalid message encoding!", new InvalidDataException());

            return cm;
        }

        /// <summary>
        /// Encrypts a message
        /// </summary>
        /// 
        /// <param name="Input">The message to encrypt</param>
        /// 
        /// <returns>The encrypted message</returns>
        /// 
        /// <exception cref="NTRUException">If not initialized, the specified hash algorithm is invalid, the encrypted data is invalid, or <c>maxLenBytes</c> is greater than 255</exception>
        public byte[] Encrypt(byte[] Input)
        {
            if (!_isInitialized)
                throw new NTRUException("NTRUEncrypt:Encrypt", "The cipher has not been initialized!", new InvalidOperationException());

            IntegerPolynomial pub = ((NTRUPublicKey)_keyPair.PublicKey).H;
            int N = _encParams.N;
            int q = _encParams.Q;
            int maxLenBytes = _encParams.MaxMsgLenBytes;
            int db = _encParams.Db;
            int bufferLenBits = _encParams.BufferLenBits;
            int dm0 = _encParams.Dm0;
            int maxM1 = _encParams.MaxM1;
            int minCallsMask = _encParams.MinMGFHashCalls;
            bool hashSeed = _encParams.HashSeed;
            int msgLen = Input.Length;

            //if (maxLenBytes > 255)
            //    throw new NTRUException("len values bigger than 255 are not supported");
            if (msgLen > maxLenBytes)
                throw new NTRUException("NTRUEncrypt:Encrypt", string.Format("Message too long: {0} > {1}!", msgLen, maxLenBytes), new InvalidDataException());

            while (true)
            {
                // M = b|octL|m|p0
                byte[] b = new byte[db / 8];
                // forward padding
                _rndEngine.GetBytes(b);
                byte[] p0 = new byte[maxLenBytes + 1 - msgLen];
                byte[] msgTmp;

                using (BinaryWriter writer = new BinaryWriter(new MemoryStream((bufferLenBits + 7) / 8)))
                {
                    writer.Write(b);
                    writer.Write((byte)msgLen);
                    writer.Write(Input);
                    writer.Write(p0);
                    msgTmp = ((MemoryStream)writer.BaseStream).ToArray();
                }

                // don't use the constant coeff if maxM1 is set; see below
                IntegerPolynomial mTrin = IntegerPolynomial.FromBinary3Sves(msgTmp, N, maxM1 > 0); 
                byte[] sData = GetSeed(Input, pub, b);
                IPolynomial r = GenerateBlindingPoly(sData);
                IntegerPolynomial R = r.Multiply(pub, q);
                byte[] oR4 = R.ToBinary4();
                IntegerPolynomial mask = MGF(oR4, N, minCallsMask, hashSeed);
                mTrin.Add(mask);

                // If df and dr are close to N/3, and the absolute value of mTrin.sumCoeffs() is
                // large enough, the message becomes vulnerable to a meet-in-the-middle attack.
                // To prevent this, we set the constant coefficient to zero but first check to ensure
                // sumCoeffs() is small enough to keep the likelihood of a decryption failure low.
                if (maxM1 > 0)
                {
                    if (mTrin.SumCoeffs() > maxM1)
                        continue;
                    mTrin.Coeffs[0] = 0;
                }

                mTrin.Mod3();

                if (mTrin.Count(-1) < dm0)
                    continue;
                if (mTrin.Count(0) < dm0)
                    continue;
                if (mTrin.Count(1) < dm0)
                    continue;

                R.Add(mTrin, q);
                R.EnsurePositive(q);

                return R.ToBinary(q);
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

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="NTRUPublicKey"/> for encryption, or a <see cref="NTRUPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="Encryption">When true cipher is for encryption, if false, decryption</param>
        /// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the NTRU public or private key</param>
        /// 
        /// <exception cref="NTRUException">Thrown if a key is invalid</exception>
        public void Initialize(bool Encryption, IAsymmetricKeyPair KeyPair)
        {

            if (!(KeyPair is NTRUKeyPair))
                throw new NTRUException("NTRUEncrypt:Initialize", "Not a valid NTRU key pair!", new InvalidDataException());

            _keyPair = (NTRUKeyPair)KeyPair;

            if (_keyPair.PublicKey == null)
                throw new NTRUException("NTRUEncrypt:Initialize", "Not a valid NTRU key pair!", new InvalidDataException());
            if (!(_keyPair.PublicKey is NTRUPublicKey))
                throw new NTRUException("NTRUEncrypt:Initialize", "Not a valid NTRU key pair!", new InvalidDataException());

            if (!Encryption)
            {
                if (_keyPair.PrivateKey == null)
                    throw new NTRUException("NTRUEncrypt:Initialize", "Not a valid NTRU key pair!", new InvalidDataException());
                if (!(_keyPair.PrivateKey is NTRUPrivateKey))
                    throw new NTRUException("NTRUEncrypt:Initialize", "Not a valid NTRU key pair!", new InvalidDataException());
            }

            _isInitialized = true;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Decrypts an integer polynomial
        /// </summary>
        /// 
        /// <param name="E">Encrypted polynomial</param>
        /// <param name="PrivT">A polynomial such that if <c>fastFp=true</c>, <c>f=1+3*priv_t</c>; otherwise, <c>f=priv_t</c></param>
        /// <param name="PrivFp">Fp</param>
        /// 
        /// <returns>Derypted polynomial</returns>
        private IntegerPolynomial Decrypt(IntegerPolynomial E, IPolynomial PrivT, IntegerPolynomial PrivFp)
        {
            int q = _encParams.Q;
            IntegerPolynomial a;

            if (_encParams.FastFp)
            {
                a = PrivT.Multiply(E, q);
                a.Multiply(3);
                a.Add(E);
            }
            else
            {
                a = PrivT.Multiply(E, q);
            }

            a.Center0(q);
            a.Mod3();
            IntegerPolynomial c = _encParams.FastFp ? a : new DenseTernaryPolynomial(a).Multiply(PrivFp, 3);
            c.Center0(3);

            return c;
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
                    throw new NTRUException("NTRUEncrypt:GetDigest", "The digest type is not supported!", new ArgumentException());
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
                    throw new NTRUException("NTRUEncrypt:GetPrng", "The prng type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Generates a seed for the Blinding Polynomial Generation Function
        /// </summary>
        /// 
        /// <param name="Message">The plain-text message</param>
        /// <param name="PubKey">The public key</param>
        /// <param name="Bits">Bits of random data</param>
        /// 
        /// <returns>A byte array containing a seed value</returns>
        private byte[] GetSeed(byte[] Message, IntegerPolynomial PubKey, byte[] Bits)
        {
            byte[] oid = _encParams.OId;
            byte[] hTrunc = PubKey.ToBinaryTrunc(_encParams.Q, _encParams.PkLen / 8);
            // sData = OID|m|b|hTrunc
            byte[] sData = new byte[oid.Length + Message.Length + Bits.Length + hTrunc.Length];

            Array.Copy(oid, 0, sData, 0, oid.Length);
            int start = oid.Length;
            Array.Copy(Message, 0, sData, start, Message.Length);
            start += Message.Length;
            Array.Copy(Bits, 0, sData, start, Bits.Length);
            start += Bits.Length;
            Array.Copy(hTrunc, 0, sData, start, hTrunc.Length);

            return sData;
        }

        /// <summary>
        /// Deterministically generates a blinding polynomial from a seed and a message representative
        /// </summary>
        /// 
        /// <param name="Seed">The seed value</param>
        /// 
        /// <returns>A blinding polynomial</returns>
        private IPolynomial GenerateBlindingPoly(byte[] Seed)
        {
            int N = _encParams.N;
            IndexGenerator ig = new IndexGenerator(Seed, _encParams);

            if (_encParams.PolyType == TernaryPolynomialType.PRODUCT) //.8, .6
            {
                SparseTernaryPolynomial r1 = SparseTernaryPolynomial.GenerateBlindingPoly(ig, N, _encParams.DR1);
                SparseTernaryPolynomial r2 = SparseTernaryPolynomial.GenerateBlindingPoly(ig, N, _encParams.DR2);
                SparseTernaryPolynomial r3 = SparseTernaryPolynomial.GenerateBlindingPoly(ig, N, _encParams.DR3);

                return new ProductFormPolynomial(r1, r2, r3);
            }
            else
            {
                if (_encParams.Sparse)
                    return SparseTernaryPolynomial.GenerateBlindingPoly(ig, N, _encParams.DR);
                else
                    return DenseTernaryPolynomial.GenerateBlindingPoly(ig, N, _encParams.DR);
            }
        }

        /// <summary>
        /// An implementation of MGF-TP-1 from P1363.1 section 8.4.1.1.
        /// </summary>
        /// 
        /// <param name="Seed">The seed value</param>
        /// <param name="N">N paramater</param>
        /// <param name="MinCallsMask">Minimum Calls Mask</param>
        /// <param name="HashSeed">Whether to hash the seed</param>
        /// 
        /// <returns></returns>
        private IntegerPolynomial MGF(byte[] Seed, int N, int MinCallsMask, bool HashSeed)
        {
            int hashLen = _dgtEngine.DigestSize;

            using (MemoryStream writer = new MemoryStream(MinCallsMask * hashLen))
            {
                byte[] Z = HashSeed ? _dgtEngine.ComputeHash(Seed) : Seed;
                int counter = 0;

                while (counter < MinCallsMask)
                {
                    byte[] data = new byte[Z.Length + 4];
                    Buffer.BlockCopy(Z, 0, data, 0, Z.Length);
                    Buffer.BlockCopy(IntUtils.IntToBytes(counter), 0, data, Z.Length, 4);
                    byte[] hash = _dgtEngine.ComputeHash(data);
                    writer.Write(hash, 0, hash.Length);
                    counter++;
                }

                IntegerPolynomial i = new IntegerPolynomial(N);
                while (true)
                {
                    int cur = 0;
                    byte[] buffer = writer.ToArray();

                    for (int j = 0; j < buffer.Length; j++)
                    {
                        int O = (int)buffer[j] & 0xFF;
                        if (O >= 243)   // 243 = 3^5
                            continue;

                        for (int terIdx = 0; terIdx < 4; terIdx++)
                        {
                            int rem3 = O % 3;
                            i.Coeffs[cur] = rem3 == 2 ? -1 : rem3;   // reduce to [-1..1] 
                            cur++;
                            if (cur == N)
                                return i;
                            O = (O - rem3) / 3;
                        }

                        i.Coeffs[cur] = O == 2 ? -1 : O;            // reduce to [-1..1] 
                        cur++;
                        if (cur == N)
                            return i;
                    }

                    if (cur >= N)
                        return i;
                    // reset the memory
                    writer.SetLength(0);
                    writer.SetLength(hashLen);
                    // get the hash
                    byte[] hash = _dgtEngine.ComputeHash(ArrayUtils.Concat(Z, IntUtils.IntToBytes(counter)));
                    writer.Write(hash, 0, hash.Length);
                    counter++;
                }
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
                    if (_rndEngine != null)
                    {
                        _rndEngine.Dispose();
                        _rndEngine = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}