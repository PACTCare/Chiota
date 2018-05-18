#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
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
// Portions of this cipher based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <a href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</a>.
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <a href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</a>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation based on the Serpent block cipher,
// using HKDF with a selectable Message Digest for expanded key generation.
// Serpent HKDF Extended (SHX)
// Written by John Underhill, November 15, 2014
// Updated October 8, 2016
// Contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block
{
    /// <summary>
    /// A Serpent cipher extended with an (optional) HKDF powered Key Schedule
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of encrypting a block:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(BlockCiphers.SHX))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, 0, Output, 0);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Description:</description>
    /// <para>SHX is a Serpent implementation that can use a standard configuration on key sizes up to 32 bytes (256 bits), 
    /// an extended key size of 64 bytes (512 bits), or unlimited key sizes greater than 64 bytes.<BR></BR>
    /// On <see cref="LegalKeySizes"/> larger than 64 bytes, an HKDF random bytes generator is used to expand the <c>working key</c> integer array.<BR></BR>
    /// In HKDF extended mode, the number of <c>transformation rounds</c> can be user assigned (through the constructor) to between 16 and 64 rounds.
    /// Increasing the number of diffusion rounds processed within the ciphers rounds function creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze.<BR></BR>
    /// SHX is capable of processing up to 64 rounds, that is twice the number of rounds used in a standard implementation of Serpent. 
    /// When using e.g. SHA-2 256, a minimum key size for is 32 bytes, further blocks of can be added to the key so long as they align; (n * hash size), ex. 64, 128, 192 bytes.. there is no upper maximum.
    /// </para>
    ///
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>An input key of up to 64 bytes in length will use a standard key schedule for internal key expansion; greater than 64 bytes implements the HKDF key schedule.</description></item>
    /// <item><description>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake2, Keccak, SHA-2 or Skein.</description></item>
    /// <item><description>The HKDF Digest engine is definable through the <see cref="SHX(int, Digests)">Constructor</see> type enumeration parameter: ExtractorType.</description></item>
    /// <item><description>Minimum HKDF key size is the Digests Hash output size, recommended is 2* the minimum, or increments of (n * hash-size) in bytes.</description></item>
    /// <item><description>The recommended size for maximum security is 2* the digests block size; this calls HKDF Extract using full blocks of key and salt.</description></item>
    /// <item><description>Valid key sizes can be determined at run time using the <see cref="LegalKeySizes"/> property.</description></item>
    /// <item><description>The internal block size is 16 bytes wide.</description></item>
    /// <item><description>Diffusion rounds assignments are 32, 40, 48, 56, and 64 rounds, default is 32 (128-256 bit key), a 512 bit key is automatically assigned 40 rounds.</description></item>
    /// <item><description>Valid rounds assignments can be found in the <see cref="LegalRounds"/> property.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Serpent: <a href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</a>.</description></item>
    /// <item><description>HMAC <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
    /// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</a>.</description></item>
    /// <item><description>HKDF <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>.</description></item>
    /// <item><description>SHA3 <a href="https://131002.net/blake/blake.pdf">The Blake digest</a>.</description></item>
    /// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
    /// <item><description>SHA3 <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class SHX : IBlockCipher
    {
        #region Constants
        private const string ALG_NAME = "SHX";
        private const int BLOCK_SIZE = 16;
        private const int ROUNDS32 = 32;
        private const int LEGAL_KEYS = 8;
        private const int MAX_ROUNDS = 64;
        private const int MIN_ROUNDS = 32;
        private const uint PHI = 0x9E3779B9;
        #endregion

        #region Fields
        private int m_rndCount = MIN_ROUNDS;
        private uint[] m_expKey;
        private bool m_isDisposed = false;
        private bool m_isEncryption;
        private IDigest m_kdfExtractor;
        private Digests m_kdfExtractorType;
        // configurable nonce can create a unique distribution, can be byte(0)
        private byte[] m_kdfInfo = System.Text.Encoding.ASCII.GetBytes("SHX version 1 information string");
        private int m_kdfInfoMax = 0;
        private int m_kdfKeySize = 0;
        private bool m_isInitialized = false;
        private int[] m_legalKeySizes = new int[LEGAL_KEYS];
        private int[] m_legalRounds;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher.
        /// <para>Block size is 16 bytes wide.</para>
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get/Set: Sets the Info value in the HKDF initialization parameters. 
        /// <para>Must be set before <see cref="Initialize(bool, KeyParams)"/> is called.
        /// Changing this code will create a unique distribution of the cipher.
        /// Code can be either a zero byte array, or a multiple of the HKDF digest engines return size.</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid distribution code is used</exception>
        public byte[] DistributionCode
        {
            get { return m_kdfInfo; }
            set
            {
                if (value == null)
                    throw new CryptoSymmetricException("SHX:DistributionCode", "Distribution Code can not be null!", new ArgumentNullException());

                m_kdfInfo = value;
            }
        }

        /// <summary>
        /// Get: The maximum size of the distribution code in bytes.
        /// <para>The distribution code can be used as a secondary source of entropy in the HKDF key expansion phase.
        /// If used as a nonce the distribution code should be secret, and equal in size to this value</para>
        /// </summary>
        public int DistributionCodeMax
        {
            get { return m_kdfInfoMax; }
        }

        /// <summary>
        /// Get: The block ciphers type name
        /// </summary>
        public BlockCiphers Enumeral
        {
            get { return BlockCiphers.Serpent; }
        }

        /// <summary>
        /// Get: Cipher is initialized for encryption, false for decryption.
        /// <para>Value set in <see cref="Initialize(bool, KeyParams)"/>.</para>
        /// </summary>
        public bool IsEncryption
        {
            get { return m_isEncryption; }
            private set { m_isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
            private set { m_isInitialized = value; }
        }

        /// <summary>
        /// Get: Available block sizes for this cipher
        /// </summary>
        public int[] LegalBlockSizes
        {
            get { return new int[] { 16 }; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public int[] LegalKeySizes
        {
            get { return m_legalKeySizes; }
            private set { m_legalKeySizes = value; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public int[] LegalRounds
        {
            get { return m_legalRounds; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: The number of diffusion rounds processed by the transform
        /// </summary>
        public int Rounds
        {
            get { return m_rndCount; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. 
        /// Default is 32 rounds; defining rounds requires HKDF extended mode.</param>
        /// <param name="ExtractorType">The Key Schedule HKDF digest engine; can be any one of the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> implementations. 
        /// The default engine is None, which invokes the standard key schedule mechanism.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public SHX(int Rounds = ROUNDS32, Digests ExtractorType = Digests.None)
        {
            LoadState(ExtractorType);

            if (ExtractorType != Digests.None)
            {
                for (int i = 0; i < m_legalRounds.Length; i++)
                {
                    if (Rounds == m_legalRounds[i])
                        break;
                    if (i == m_legalRounds.Length - 1)
                        throw new CryptoSymmetricException("SHX:CTor", "Invalid rounds count! Rounds must be a LegalRounds size!", new ArgumentOutOfRangeException());
                }
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SHX()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output arrays must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Decrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Decrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Encrypt a block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            Encrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Encrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Encrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key container.<para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("SHX:Initialize", "Invalid key! Key can not be null.", new ArgumentNullException());

            for (int i = 0; i < LegalKeySizes.Length; i++)
            {
                if (KeyParam.Key.Length == LegalKeySizes[i])
                    break;
                if (i == LegalKeySizes.Length - 1)
                    throw new CryptoSymmetricException("SHX:Initialize", "Invalid key size! Key must be a legal key size!", new ArgumentOutOfRangeException());
            }

            // get the kdf digest engine
            if (m_kdfExtractorType != Digests.None)
            {
                if (KeyParam.Key.Length < m_kdfKeySize)
                    throw new CryptoSymmetricException("SHX:Initialize", "Invalid key! HKDF extended mode requires key be at least digests output size.", new ArgumentNullException());

                m_kdfExtractor = LoadDigest(m_kdfExtractorType);

                if (KeyParam.IKM.Length > m_kdfInfoMax)
                    throw new CryptoSymmetricException("SHX:Initialize", "Invalid info size! Info parameter must be no longer than DistributionCodeMax size.");
                if (KeyParam.IKM.Length > 0)
                    m_kdfInfo = KeyParam.IKM;
            }

            m_isEncryption = Encryption;
            // generate the round keys
            ExpandKey(KeyParam.Key);
            // ready to transform data
            m_isInitialized = true;
        }

        /// <summary>
        /// Transform a block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt or Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (m_isEncryption)
                Encrypt16(Input, 0, Output, 0);
            else
                Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (m_isEncryption)
                Encrypt16(Input, InOffset, Output, OutOffset);
            else
                Decrypt16(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private void ExpandKey(byte[] Key)
        {
            if (m_kdfExtractorType != Digests.None)
            {
                // using hkdf expansion
                m_expKey = SecureExpand(Key);
            }
            else
            {
                // standard serpent key expansion + k512
                m_expKey = StandardExpand(Key);
            }
        }

        private uint[] SecureExpand(byte[] Key)
        {
            // expanded key size
            int keySize = 4 * (m_rndCount + 1);
            // hkdf return array
            int keyBytes = keySize * 4;
            byte[] rawKey = new byte[keyBytes];

            HKDF gen = new HKDF(m_kdfExtractor);

            // change 1.2: use extract only on an oversized key
            if (Key.Length > m_kdfExtractor.BlockSize)
            {
                // seperate salt and key
                m_kdfKeySize = m_kdfExtractor.BlockSize;
                byte[] kdfKey = new byte[m_kdfKeySize];
                Buffer.BlockCopy(Key, 0, kdfKey, 0, m_kdfKeySize);
                int saltSize = Key.Length - m_kdfKeySize;
                byte[] kdfSalt = new byte[saltSize];
                Buffer.BlockCopy(Key, m_kdfKeySize, kdfSalt, 0, saltSize);
                // info can be null
                gen.Initialize(kdfKey, kdfSalt, m_kdfInfo);
            }
            else
            {
                if (m_kdfInfo.Length != 0)
                    gen.Info = m_kdfInfo;

                gen.Initialize(Key);
            }

            gen.Generate(rawKey);
            gen.Dispose();

            // initialize working key
            uint[] expKey = new uint[keySize];
            // copy bytes to working key
            Buffer.BlockCopy(rawKey, 0, expKey, 0, keyBytes);

            return expKey;
        }

        private uint[] StandardExpand(byte[] Key)
        {
            int cnt = 0;
            int index = 0;
            int padSize = Key.Length < 32 ? 16 : Key.Length / 2;
            uint[] tmpKey = new uint[padSize];
            int offset = 0;

            // CHANGE: 512 key gets 8 extra rounds
            m_rndCount = (Key.Length == 64) ? 40 : ROUNDS32;
            int keySize = 4 * (m_rndCount + 1);

            // step 1: reverse copy key to temp array
            for (offset = Key.Length; offset > 0; offset -= 4)
                tmpKey[index++] = IntUtils.BytesToBe32(Key, offset - 4);

            // pad small key
            if (index < 8)
                tmpKey[index] = 1;

            // initialize the key
            uint[] expKey = new uint[keySize];

            if (padSize == 16)
            {
                // 32 byte key
                // step 2: rotate k into w(k) ints
                for (int i = 8; i < 16; i++)
                    tmpKey[i] = IntUtils.RotateLeft((uint)(tmpKey[i - 8] ^ tmpKey[i - 5] ^ tmpKey[i - 3] ^ tmpKey[i - 1] ^ PHI ^ (i - 8)), 11);

                // copy to expanded key
                Array.Copy(tmpKey, 8, expKey, 0, 8);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 8; i < keySize; i++)
                    expKey[i] = IntUtils.RotateLeft((uint)(expKey[i - 8] ^ expKey[i - 5] ^ expKey[i - 3] ^ expKey[i - 1] ^ PHI ^ i), 11);
            }
            else
            {
                // *extended*: 64 byte key
                // step 3: rotate k into w(k) ints, with extended polynominal
                // Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
                for (int i = 16; i < 32; i++)
                    tmpKey[i] = IntUtils.RotateLeft((uint)(tmpKey[i - 16] ^ tmpKey[i - 13] ^ tmpKey[i - 11] ^ tmpKey[i - 10] ^ tmpKey[i - 8] ^ tmpKey[i - 5] ^ tmpKey[i - 3] ^ tmpKey[i - 1] ^ PHI ^ (i - 16)), 11);

                // copy to expanded key
                Array.Copy(tmpKey, 16, expKey, 0, 16);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 16; i < keySize; i++)
                    expKey[i] = IntUtils.RotateLeft((uint)(expKey[i - 16] ^ expKey[i - 13] ^ expKey[i - 11] ^ expKey[i - 10] ^ expKey[i - 8] ^ expKey[i - 5] ^ expKey[i - 3] ^ expKey[i - 1] ^ PHI ^ i), 11);
            }

            // step 4: create the working keys by processing with the Sbox and IP
            while (cnt < keySize - 4)
            {
                Sb3(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb2(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb1(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb0(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb7(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb6(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb5(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb4(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
            }

            // last round
            Sb3(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]);

            return expKey;
        }
        #endregion

        #region Rounds Processing
        private void Decrypt16(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int LRD = 4;
            int keyCtr = m_expKey.Length;

            // input round
            uint R3 = m_expKey[--keyCtr] ^ IntUtils.BytesToLe32(Input, InOffset + 12);
            uint R2 = m_expKey[--keyCtr] ^ IntUtils.BytesToLe32(Input, InOffset + 8);
            uint R1 = m_expKey[--keyCtr] ^ IntUtils.BytesToLe32(Input, InOffset + 4);
            uint R0 = m_expKey[--keyCtr] ^ IntUtils.BytesToLe32(Input, InOffset);

            // process 8 round blocks
            do
            {
                Ib7(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib6(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib5(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib4(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib3(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib2(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib1(ref R0, ref R1, ref R2, ref R3);
                R3 ^= m_expKey[--keyCtr];
                R2 ^= m_expKey[--keyCtr];
                R1 ^= m_expKey[--keyCtr];
                R0 ^= m_expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib0(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr != LRD)
                {
                    R3 ^= m_expKey[--keyCtr];
                    R2 ^= m_expKey[--keyCtr];
                    R1 ^= m_expKey[--keyCtr];
                    R0 ^= m_expKey[--keyCtr];
                    InverseTransform(ref R0, ref R1, ref R2, ref R3);
                }
            }
            while (keyCtr != LRD);

            // last round
            IntUtils.Le32ToBytes(R3 ^ m_expKey[--keyCtr], Output, OutOffset + 12);
            IntUtils.Le32ToBytes(R2 ^ m_expKey[--keyCtr], Output, OutOffset + 8);
            IntUtils.Le32ToBytes(R1 ^ m_expKey[--keyCtr], Output, OutOffset + 4);
            IntUtils.Le32ToBytes(R0 ^ m_expKey[--keyCtr], Output, OutOffset);
        }

        private void Encrypt16(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int LRD = m_expKey.Length - 5;
            int keyCtr = -1;

            // input round
            uint R0 = IntUtils.BytesToLe32(Input, InOffset);
            uint R1 = IntUtils.BytesToLe32(Input, InOffset + 4);
            uint R2 = IntUtils.BytesToLe32(Input, InOffset + 8);
            uint R3 = IntUtils.BytesToLe32(Input, InOffset + 12);

            // process 8 round blocks
            do
            {
                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb0(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb1(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb2(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3); ;

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb3(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb4(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb5(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb6(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= m_expKey[++keyCtr];
                R1 ^= m_expKey[++keyCtr];
                R2 ^= m_expKey[++keyCtr];
                R3 ^= m_expKey[++keyCtr];
                Sb7(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr != LRD)
                    LinearTransform(ref R0, ref R1, ref R2, ref R3);
            }
            while (keyCtr != LRD);

            // last round
            IntUtils.Le32ToBytes(m_expKey[++keyCtr] ^ R0, Output, OutOffset);
            IntUtils.Le32ToBytes(m_expKey[++keyCtr] ^ R1, Output, OutOffset + 4);
            IntUtils.Le32ToBytes(m_expKey[++keyCtr] ^ R2, Output, OutOffset + 8);
            IntUtils.Le32ToBytes(m_expKey[++keyCtr] ^ R3, Output, OutOffset + 12);
        }
        #endregion

        #region SBox Calculations
        private void Sb0(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R0 ^ R3;
            uint t2 = R2 ^ t1;
            uint t3 = R1 ^ t2;
            R3 = (R0 & R3) ^ t3;
            uint t4 = R0 ^ (R1 & t1);
            R2 = t3 ^ (R2 | t4);
            R0 = R3 & (t2 ^ t4);
            R1 = (~t2) ^ R0;
            R0 ^= (~t4);
        }

        private void Ib0(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = ~R0;
            uint t2 = R0 ^ R1;
            uint t3 = R3 ^ (t1 | t2);
            uint t4 = R2 ^ t3;
            R2 = t2 ^ t4;
            uint t5 = t1 ^ (R3 & t2);
            R1 = t3 ^ (R2 & t5);
            R3 = (R0 & t3) ^ (t4 | R1);
            R0 = R3 ^ (t4 ^ t5);
        }

        private void Sb1(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R1 ^ (~R0);
            uint t2 = R2 ^ (R0 | t1);
            R2 = R3 ^ t2;
            uint t3 = R1 ^ (R3 | t1);
            uint t4 = t1 ^ R2;
            R3 = t4 ^ (t2 & t3);
            uint t5 = t2 ^ t3;
            R1 = R3 ^ t5;
            R0 = t2 ^ (t4 & t5);
        }

        private void Ib1(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R1 ^ R3;
            uint t2 = R0 ^ (R1 & t1);
            uint t3 = t1 ^ t2;
            R3 = R2 ^ t3;
            uint t4 = R1 ^ (t1 & t2);
            R1 = t2 ^ (R3 | t4);
            uint t5 = ~R1;
            uint t6 = R3 ^ t4;
            R0 = t5 ^ t6;
            R2 = t3 ^ (t5 | t6);
        }

        private void Sb2(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = ~R0;
            uint t2 = R1 ^ R3;
            uint t3 = t2 ^ (R2 & t1);
            uint t4 = R2 ^ t1;
            uint t5 = R1 & (R2 ^ t3);
            uint t6 = t4 ^ t5;
            R2 = R0 ^ ((R3 | t5) & (t3 | t4));
            R1 = (t2 ^ t6) ^ (R2 ^ (R3 | t1));
            R0 = t3;
            R3 = t6;
        }

        private void Ib2(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R1 ^ R3;
            uint t2 = R0 ^ R2;
            uint t3 = R2 ^ t1;
            uint t4 = R0 | ~t1;
            R0 = t2 ^ (R1 & t3);
            uint t5 = t1 ^ (t2 | (R3 ^ t4));
            uint t6 = ~t3;
            uint t7 = R0 | t5;
            R1 = t6 ^ t7;
            R2 = (R3 & t6) ^ (t2 ^ t7);
            R3 = t5;
        }

        private void Sb3(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R0 ^ R1;
            uint t2 = R0 | R3;
            uint t3 = R2 ^ R3;
            uint t4 = (R0 & R2) | (t1 & t2);
            R2 = t3 ^ t4;
            uint t5 = t4 ^ (R1 ^ t2);
            R0 = t1 ^ (t3 & t5);
            uint t6 = R2 & R0;
            R3 = (R1 | R3) ^ (t3 ^ t6);
            R1 = t5 ^ t6;
        }

        private void Ib3(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R1 ^ R2;
            uint t2 = R0 ^ (R1 & t1);
            uint t3 = R3 | t2;
            uint t4 = R3 ^ (t1 | t3);
            R2 = (R2 ^ t2) ^ t4;
            uint t5 = (R0 | R1) ^ t4;
            R0 = t1 ^ t3;
            R3 = t2 ^ (R0 & t5);
            R1 = R3 ^ (R0 ^ t5);
        }

        private void Sb4(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R0 ^ R3;
            uint t2 = R2 ^ (R3 & t1);
            uint t3 = R1 | t2;
            R3 = t1 ^ t3;
            uint t4 = ~R1;
            uint t5 = t2 ^ (t1 | t4);
            uint t6 = t1 ^ t4;
            uint t7 = (R0 & t5) ^ (t3 & t6);
            R1 = (R0 ^ t2) ^ (t6 & t7);
            R0 = t5;
            R2 = t7;
        }

        private void Ib4(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R1 ^ (R0 & (R2 | R3));
            uint t2 = R2 ^ (R0 & t1);
            uint t3 = R3 ^ t2;
            uint t4 = ~R0;
            uint t5 = t1 ^ (t2 & t3);
            uint t6 = R3 ^ (t3 | t4);
            R1 = t3;
            R0 = t5 ^ t6;
            R2 = (t1 & t6) ^ (t3 ^ t4);
            R3 = t5;
        }

        private void Sb5(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = ~R0;
            uint t2 = R0 ^ R1;
            uint t3 = R0 ^ R3;
            uint t4 = (R2 ^ t1) ^ (t2 | t3);
            uint t5 = R3 & t4;
            uint t6 = t5 ^ (t2 ^ t4);
            uint t7 = t3 ^ (t1 | t4);
            R2 = (t2 | t5) ^ t7;
            R3 = (R1 ^ t5) ^ (t6 & t7);
            R0 = t4;
            R1 = t6;
        }

        private void Ib5(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = ~R2;
            uint t2 = R3 ^ (R1 & t1);
            uint t3 = R0 & t2;
            uint t4 = t3 ^ (R1 ^ t1);
            uint t5 = R1 | t4;
            uint t6 = t2 ^ (R0 & t5);
            uint t7 = R0 | R3;
            R2 = (R1 & t7) ^ (t3 | (R0 ^ R2));
            R0 = t7 ^ (t1 ^ t5);
            R1 = t6;
            R3 = t4;
        }

        private void Sb6(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R0 ^ R3;
            uint t2 = R1 ^ t1;
            uint t3 = R2 ^ (~R0 | t1);
            R1 ^= t3;
            uint t4 = R3 ^ (t1 | R1);
            R2 = t2 ^ (t3 & t4);
            uint t5 = t3 ^ t4;
            R0 = R2 ^ t5;
            R3 = (~t3) ^ (t2 & t5);
        }

        private void Ib6(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = ~R0;
            uint t2 = R0 ^ R1;
            uint t3 = R2 ^ t2;
            uint t4 = R3 ^ (R2 | t1);
            uint t5 = t3 ^ t4;
            uint t6 = t2 ^ (t3 & t4);
            uint t7 = t4 ^ (R1 | t6);
            uint t8 = R1 | t7;
            R0 = t6 ^ t8;
            R2 = (R3 & t1) ^ (t3 ^ t8);
            R1 = t5;
            R3 = t7;
        }

        private void Sb7(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R1 ^ R2;
            uint t2 = R3 ^ (R2 & t1);
            uint t3 = R0 ^ t2;
            R1 ^= (t3 & (R3 | t1));
            uint t4 = t1 ^ (R0 & t3);
            uint t5 = t3 ^ (t2 | R1);
            R2 = t2 ^ (t4 & t5);
            R0 = (~t5) ^ (t4 & R2);
            R3 = t4;
        }

        private void Ib7(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint t1 = R2 | (R0 & R1);
            uint t2 = R3 & (R0 | R1);
            uint t3 = t1 ^ t2;
            uint t4 = R1 ^ t2;
            R1 = R0 ^ (t4 | (t3 ^ ~R3));
            uint t8 = (R2 ^ t4) ^ (R3 | R1);
            R2 = (t1 ^ R1) ^ (t8 ^ (R0 & t3));
            R0 = t8;
            R3 = t3;
        }

        /// <remarks>
        /// Apply the linear transformation to the register set
        /// </remarks>
        private void LinearTransform(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint x0 = IntUtils.RotateLeft(R0, 13);
            uint x2 = IntUtils.RotateLeft(R2, 3);
            uint x1 = R1 ^ x0 ^ x2;
            uint x3 = R3 ^ x2 ^ x0 << 3;

            R1 = IntUtils.RotateLeft(x1, 1);
            R3 = IntUtils.RotateLeft(x3, 7);
            R0 = IntUtils.RotateLeft(x0 ^ R1 ^ R3, 5);
            R2 = IntUtils.RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
        }

        /// <remarks>
        /// Apply the inverse of the linear transformation to the register set
        /// </remarks>
        private void InverseTransform(ref uint R0, ref uint R1, ref uint R2, ref uint R3)
        {
            uint x2 = IntUtils.RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
            uint x0 = IntUtils.RotateRight(R0, 5) ^ R1 ^ R3;
            uint x3 = IntUtils.RotateRight(R3, 7);
            uint x1 = IntUtils.RotateRight(R1, 1);

            R3 = x3 ^ x2 ^ x0 << 3;
            R1 = x1 ^ x0 ^ x2;
            R2 = IntUtils.RotateRight(x2, 3);
            R0 = IntUtils.RotateRight(x0, 13);
        }
        #endregion

        #region Helpers
        private IDigest LoadDigest(Digests KeyEngine)
        {
            try
            {
                return DigestFromName.GetInstance(KeyEngine);
            }
            catch
            {
                throw new CryptoSymmetricException("RHX:GetKeyEngine", "The digest type is not supported!", new ArgumentException());
            }
        }

        private void LoadState(Digests ExtractorType)
        {
            m_kdfExtractorType = ExtractorType;

            if (m_kdfExtractorType == Digests.None)
            {
                m_legalRounds = new int[] { 32, 40 };
                m_legalKeySizes = new int[] { 16, 24, 32, 64 };
            }
            else
            {
                m_legalRounds = new int[] { 32, 40, 48, 56, 64 };
                m_kdfKeySize = DigestFromName.GetBlockSize(m_kdfExtractorType);
                // calculate max saturation of entropy when distribution code is used as key extension; subtract hash finalizer padding + 1 byte kdf counter
                m_kdfInfoMax = m_kdfKeySize - (DigestFromName.GetPaddingSize(m_kdfExtractorType) + 1);
                m_legalKeySizes = new int[3];
                m_legalKeySizes[0] = DigestFromName.GetDigestSize(m_kdfExtractorType);
                m_legalKeySizes[1] = m_kdfKeySize;
                m_legalKeySizes[2] = m_kdfKeySize * 2;
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
                    if (m_kdfExtractor != null)
                    {
                        m_kdfExtractor.Dispose();
                        m_kdfExtractor = null;
                    }
                    if (m_expKey != null)
                    {
                        Array.Clear(m_expKey, 0, m_expKey.Length);
                        m_expKey = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
