#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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
// Portions of this cipher partially based on the Twofish block cipher designed by Bruce Schneier, John Kelsey, 
// Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson.
// Twofish: <see href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</see>.
// 
// Portions of this cipher also based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <see href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</see>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation based on the Twofish and Serpent Merged block ciphers,
// using HKDF with a selectable Message Digest for expanded key generation.
// Merges both diffusion engines during rounds processing.
// Twofish + Serpent Merged Cryptographic Primitives (TS-MCP or just TSM).
// Written by John Underhill, December 13 27, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block
{
    /// <summary>
    /// <h3>TSM: An implementation based on the Twofish and Serpent Merged block ciphers, extended with an HKDF powered Key Schedule.</h3>
    /// <para>TSM is Twofish<cite>Twofish</cite> and Serpent<cite>Serpent</cite> ciphers, merged within the rounds function.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new TSM()))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/09/18" version="1.2.0.0">Initial release using a fixed Digest key schedule generator</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Secondary release using an assignable Digest in the HKDF engine</revision>
    /// <revision date="2015/03/15" version="1.3.2.0">Added the IkmSize optional parameter to the constructor, and the DistributionCode property</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description><see cref="HKDF">HKDF</see> Digest <see cref="Digests">engine</see> is definable through the <see cref="TSM(int, Digests)">Constructor</see> parameter: KeyEngine.</description></item>
    /// <item><description>Key Schedule is powered by a Hash based Key Derivation Function using a definable <see cref="IDigest">Digest</see>.</description></item>
    /// <item><description>Minimum key size is (IKm + Salt) (N * Digest State Size) + (Digest Hash Size) in bytes.</description></item>
    /// <item><description>Valid block size is 16 bytes wide.</description></item>
    /// <item><description>Valid Rounds assignments are 16, 24, and 32, default is 16.</description></item>
    /// </list>
    /// 
    /// <para>The transform combines the two ciphers within the rounds function processing loop. 
    /// In the rounds functions, a round of Twofish is processed; the permuted product of that transformation is then transformed again by a round of Serpent.
    /// This alternating of state transformations between two very strong cryptographic primitives, both creates a highly diffused output, and creates a cipher 
    /// that is very resistant to cryptanalysis.</para>
    /// 
    /// <para>The key schedule in TSM powered by an HKDF<cite>RFC 5869</cite> generator, using a Digest HMAC<cite>RFC 2104</cite> (Hash based Message Authentication Code) as its random engine. 
    /// This is one of the strongest<cite>Fips 198-1</cite> methods available for generating pseudo-random keying material, and far superior in entropy dispersion to Rijndael, or even Serpents key schedule. HKDF uses up to three inputs; a nonce value called an information string, an Ikm (Input keying material), and a Salt value. 
    /// The HMAC RFC 2104, recommends a key size equal to the digest output, in the case of SHA512, 64 bytes, anything larger gets passed through the hash function to get the required 512 bit key size. 
    /// The Salt size is a minimum of the hash functions block size, with SHA-2 512 that is 128 bytes.</para>
    /// 
    /// <para>When using SHA-2 512, a minimum key size for RSM is 192 bytes, further blocks of salt can be added to the key so long as they align; ikm + (n * blocksize), ex. 192, 320, 448 bytes.. there is no upper maximum. 
    /// This means that you can create keys as large as you like so long as it falls on these boundaries, this effectively eliminates brute force as a means of attack on the cipher, even in quantum terms.</para> 
    /// 
    /// <para>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake<cite>Blake</cite>, Keccak<cite>Keccak</cite>, SHA-2<cite>Fips 180-4</cite>, or Skein<cite>Skein</cite>.
    /// The default Digest Engine is SHA-2 512.</para>
    /// 
    /// <para>The legal key sizes are determined by a combination of the (Hash Size + a Multiplier * the Digest State Size); <math>klen = h + (n * s)</math>, this will vary between Digest implementations. 
    /// Correct key sizes can be determined at runtime using the <see cref="LegalKeySizes"/> property.</para>
    /// 
    /// <para>The number of diffusion rounds processed within the ciphers rounds function can also be defined; adding rounds creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze. 
    /// TSM is capable of processing up to 32 rounds, that is twice the number of rounds used in a standard implementation of Twofish. 
    /// Valid rounds assignments can be found in the <see cref="LegalRounds"/> static property.</para>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Twofish: <see href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</see>.</description></item>
    /// <item><description>Serpent: <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.</description></item>
    /// <item><description>HMAC: <see href="http://tools.ietf.org/html/rfc2104">RFC 2104</see>.</description></item>
    /// <item><description>NIST: <see href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">Fips 198.1</see>.</description></item>
    /// <item><description>HKDF: <see href="http://tools.ietf.org/html/rfc5869">RFC 5869</see>.</description></item>
    /// <item><description>NIST: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class TSM : IBlockCipher
    {
        #region Constants
        private const string ALG_NAME = "TSM";
        private const Int32 BLOCK_SIZE = 16;
        private const Int32 ROUNDS16 = 16;
        private const Int32 DEFAULT_SUBKEYS = 40;
        private const Int32 GF256_FDBK = 0x169; // primitive polynomial for GF(256)
        private const Int32 GF256_FDBK_2 = GF256_FDBK / 2;
        private const Int32 GF256_FDBK_4 = GF256_FDBK / 4;
        private const Int32 KEY_BITS = 256;
        private const Int32 LEGAL_KEYS = 10;
        private const Int32 RS_GF_FDBK = 0x14D; // field generator
        private const Int32 SK_STEP = 0x02020202;
        private const Int32 SK_BUMP = 0x01010101;
        private const Int32 SK_ROTL = 9;
        private const Int32 SBOX_SIZE = 1024;
        #endregion

        #region Fields
        private Int32 _dfnRounds = ROUNDS16;
        // configurable nonce can create a unique distribution, can be byte(0)
        private byte[] _hkdfInfo = System.Text.Encoding.ASCII.GetBytes("TSM version 1 information string");
        private IDigest _keyEngine;
        private Int32[] _expKey;
        private Int32 _ikmSize = 0;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private int[] _legalKeySizes = new int[LEGAL_KEYS];
        private Int32[] _sprBox = new Int32[SBOX_SIZE];
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
            get { return _hkdfInfo; }
            set
            {
                if (value == null)
                    throw new CryptoSymmetricException("TSM:DistributionCode", "Distribution Code can not be null!", new ArgumentNullException());

                _hkdfInfo = value;
            }
        }

        /// <summary>
        /// Get/Set: Specify the size of the HMAC key; extracted from the cipher key.
        /// <para>This property can only be changed before the Initialize function is called.</para>
        /// <para>Default is the digest return size; can only be a multiple of that length.
        /// Maximum size is the digests underlying block size; if the key
        /// is longer than this, the size will default to the block size.</para>
        /// </summary>
        public int IkmSize
        {
            get { return _ikmSize; }
            set
            {
                if (value == 0)
                    _ikmSize = _keyEngine.DigestSize;
                if (value < _keyEngine.DigestSize)
                    _ikmSize = _keyEngine.DigestSize;
                else if (value > _keyEngine.BlockSize)
                    _ikmSize = _keyEngine.BlockSize;
                else if (value % _keyEngine.DigestSize > 0)
                    _ikmSize = value - (value % _keyEngine.DigestSize);
                else
                    _ikmSize = _keyEngine.DigestSize;
            }
        }

        /// <summary>
        /// Get: Initialized for encryption, false for decryption.
        /// <para>Value set in <see cref="Initialize(bool, KeyParams)"/>.</para>
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: Available block sizes for this cipher
        /// </summary>
        public static int[] LegalBlockSizes
        {
            get { return new int[] { 16 }; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public Int32[] LegalKeySizes
        {
            get { return _legalKeySizes; }
            private set { _legalKeySizes = value; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static int[] LegalRounds
        {
            get { return new int[] { 16, 24, 32 }; }
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
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 16 rounds.</param>
        /// <param name="KeyEngine">The Key Schedule KDF digest engine; can be any one of the <see cref="Digests">Digest</see> implementations. The default engine is <see cref="SHA512"/>.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public TSM(int Rounds = ROUNDS16, Digests KeyEngine = Digests.SHA512)
        {
            if (Rounds != 16 && Rounds != 24 && Rounds != 32)
                throw new CryptoSymmetricException("TSM:CTor", "Invalid rounds size! Sizes supported are 16, 24, and 32.", new ArgumentOutOfRangeException());

            // get the kdf digest engine
            _keyEngine = GetKeyEngine(KeyEngine);
            // set the hmac key size
            _ikmSize = _ikmSize == 0 ? _keyEngine.DigestSize : _ikmSize;

            for (int i = 0; i < _legalKeySizes.Length; i++)
                _legalKeySizes[i] = (_keyEngine.BlockSize * (i + 1)) + _ikmSize;

            _dfnRounds = Rounds;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~TSM()
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
        /// <param name="KeyParam">Cipher key container. <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("TSM:Initialize", "Invalid key! Key can not be null.", new ArgumentNullException());
            if (KeyParam.Key.Length < LegalKeySizes[0])
                throw new CryptoSymmetricException("TSM:Initialize", String.Format("Invalid key size! Key must be at least {0}  bytes ({1} bit).", LegalKeySizes[0], LegalKeySizes[0] * 8), new ArgumentOutOfRangeException());
            if ((KeyParam.Key.Length - _keyEngine.DigestSize) % _keyEngine.BlockSize != 0)
                throw new CryptoSymmetricException("TSM:Initialize", String.Format("Invalid key size! Key must be (length - IKm length: {0} bytes) + multiple of {1} block size.", _keyEngine.DigestSize, _keyEngine.BlockSize), new ArgumentOutOfRangeException());

            _isEncryption = Encryption;
            // expand the key
            _expKey = ExpandKey(KeyParam.Key);
            // ready to transform data
            _isInitialized = true;
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
            if (_isEncryption)
                EncryptBlock(Input, Output);
            else
                DecryptBlock(Input, Output);
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
            if (_isEncryption)
                EncryptBlock(Input, InOffset, Output, OutOffset);
            else
                DecryptBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private Int32[] ExpandKey(byte[] Key)
        {
            Int32 Y0, Y1, Y2, Y3;
            int k64Cnt = 8;
            int keyCtr = 0;
            int keySize = _dfnRounds * 2 + 8;
            int kbtSize = keySize * 4;
            byte[] rawKey = new byte[kbtSize];
            byte[] sbKey = new byte[32];
            Int32[] eKm = new Int32[k64Cnt];
            Int32[] oKm = new Int32[k64Cnt];
            Int32[] wK = new Int32[keySize];

            int saltSize = Key.Length - _ikmSize;

            // salt must be divisible of hash blocksize
            if (saltSize % _keyEngine.BlockSize != 0)
                saltSize = saltSize - saltSize % _keyEngine.BlockSize;

            // hkdf input
            byte[] hkdfKey = new byte[_ikmSize];
            byte[] hkdfSalt = new byte[saltSize];

            // copy hkdf key and salt from user key
            Buffer.BlockCopy(Key, 0, hkdfKey, 0, _ikmSize);
            Buffer.BlockCopy(Key, _ikmSize, hkdfSalt, 0, saltSize);

            // HKDF generator expands array using an SHA512 HMAC
            using (HKDF gen = new HKDF(_keyEngine, false))
            {
                gen.Initialize(hkdfSalt, hkdfKey, _hkdfInfo);
                gen.Generate(rawKey);
            }

            // copy bytes to working key
            Buffer.BlockCopy(rawKey, 0, wK, 0, kbtSize);

            for (int i = 0; i < k64Cnt; i++)
            {
                // round key material
                eKm[i] = BytesToInt32(rawKey, keyCtr);
                keyCtr += 4;
                oKm[i] = BytesToInt32(rawKey, keyCtr);
                keyCtr += 4;
                // sbox key material
                Int32ToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((4 * k64Cnt) - 4) - (i * 4));
            }

            keyCtr = 0;

            // create keyed sbox
            while (keyCtr < KEY_BITS)
            {
                Y0 = Y1 = Y2 = Y3 = keyCtr;

                Y0 = (byte)Q1[Y0] ^ sbKey[28];
                Y1 = (byte)Q0[Y1] ^ sbKey[29];
                Y2 = (byte)Q0[Y2] ^ sbKey[30];
                Y3 = (byte)Q1[Y3] ^ sbKey[31];

                Y0 = (byte)Q1[Y0] ^ sbKey[24];
                Y1 = (byte)Q1[Y1] ^ sbKey[25];
                Y2 = (byte)Q0[Y2] ^ sbKey[26];
                Y3 = (byte)Q0[Y3] ^ sbKey[27];

                Y0 = (byte)Q0[Y0] ^ sbKey[20];
                Y1 = (byte)Q1[Y1] ^ sbKey[21];
                Y2 = (byte)Q1[Y2] ^ sbKey[22];
                Y3 = (byte)Q0[Y3] ^ sbKey[23];

                Y0 = (byte)Q0[Y0] ^ sbKey[16];
                Y1 = (byte)Q0[Y1] ^ sbKey[17];
                Y2 = (byte)Q1[Y2] ^ sbKey[18];
                Y3 = (byte)Q1[Y3] ^ sbKey[19];

                Y0 = (byte)Q1[Y0] ^ sbKey[12];
                Y1 = (byte)Q0[Y1] ^ sbKey[13];
                Y2 = (byte)Q0[Y2] ^ sbKey[14];
                Y3 = (byte)Q1[Y3] ^ sbKey[15];

                Y0 = (byte)Q1[Y0] ^ sbKey[8];
                Y1 = (byte)Q1[Y1] ^ sbKey[9];
                Y2 = (byte)Q0[Y2] ^ sbKey[10];
                Y3 = (byte)Q0[Y3] ^ sbKey[11];

                // sbox members as MDS matrix multiplies 
                _sprBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
                _sprBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
                _sprBox[(keyCtr * 2) + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
                _sprBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
            }

            return wK;
        }

        private IDigest GetKeyEngine(Digests KeyEngine)
        {
            switch (KeyEngine)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
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
                    throw new CryptoSymmetricException("TSM:GetKeyEngine", "The digest type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region Rounds Processing
        private void Decrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            Int32 keyCtr = 4;
            Int32 T0, T1;
            Int32 X2 = BytesToInt32(Input, InOffset) ^ _expKey[keyCtr++];
            Int32 X3 = BytesToInt32(Input, InOffset + 4) ^ _expKey[keyCtr++];
            Int32 X0 = BytesToInt32(Input, InOffset + 8) ^ _expKey[keyCtr++];
            Int32 X1 = BytesToInt32(Input, InOffset + 12) ^ _expKey[keyCtr];

            keyCtr = _expKey.Length - 1;
            int index = 7;

            while (keyCtr > 8)
            {
                // twofish round
                T0 = Fe0(X2);
                T1 = Fe3(X3);
                X1 ^= T0 + 2 * T1 + _expKey[keyCtr--];
                X0 = (X0 << 1 | (Int32)((UInt32)X0 >> 31)) ^ (T0 + T1 + _expKey[keyCtr--]);
                X1 = (Int32)((UInt32)X1 >> 1) | X1 << 31;

                // serpent inverse sbox and transform
                InverseTransform(ref X0, ref X1, ref X2, ref X3);
                InverseBox(index--, ref X0, ref X1, ref X2, ref X3);

                // twofish round
                T0 = Fe0(X0);
                T1 = Fe3(X1);
                X3 ^= T0 + 2 * T1 + _expKey[keyCtr--];
                X2 = (X2 << 1 | (Int32)((UInt32)X2 >> 31)) ^ (T0 + T1 + _expKey[keyCtr--]);
                X3 = (Int32)((UInt32)X3 >> 1) | X3 << 31;

                // serpent round
                InverseTransform(ref X0, ref X1, ref X2, ref X3);
                InverseBox(index--, ref X0, ref X1, ref X2, ref X3);

                if (index < 0)
                    index = 7;
            }

            keyCtr = 0;
            Int32ToBytes(X0 ^ _expKey[keyCtr++], Output, OutOffset);
            Int32ToBytes(X1 ^ _expKey[keyCtr++], Output, OutOffset + 4);
            Int32ToBytes(X2 ^ _expKey[keyCtr++], Output, OutOffset + 8);
            Int32ToBytes(X3 ^ _expKey[keyCtr], Output, OutOffset + 12);
        }

        private void Encrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            Int32 keyCtr = 0;
            Int32 T0, T1;
            Int32 X0 = BytesToInt32(Input, InOffset) ^ _expKey[keyCtr++];
            Int32 X1 = BytesToInt32(Input, InOffset + 4) ^ _expKey[keyCtr++];
            Int32 X2 = BytesToInt32(Input, InOffset + 8) ^ _expKey[keyCtr++];
            Int32 X3 = BytesToInt32(Input, InOffset + 12) ^ _expKey[keyCtr];

            keyCtr = 8;
            int index = 0;

            while (keyCtr < _expKey.Length)
            {
                // serpent sbox and transform
                SuperBox(index++, ref X0, ref X1, ref X2, ref X3);
                LinearTransform(ref X0, ref X1, ref X2, ref X3);

                // twofish round
                T0 = Fe0(X0);
                T1 = Fe3(X1);
                X2 ^= T0 + T1 + _expKey[keyCtr++];
                X2 = (Int32)((UInt32)X2 >> 1) | X2 << 31;
                X3 = (X3 << 1 | (Int32)((UInt32)X3 >> 31)) ^ (T0 + 2 * T1 + _expKey[keyCtr++]);

                // serpent round
                SuperBox(index++, ref X0, ref X1, ref X2, ref X3);
                LinearTransform(ref X0, ref X1, ref X2, ref X3);

                // twofish round
                T0 = Fe0(X2);
                T1 = Fe3(X3);
                X0 ^= T0 + T1 + _expKey[keyCtr++];
                X0 = (Int32)((UInt32)X0 >> 1) | X0 << 31;
                X1 = (X1 << 1 | (Int32)((UInt32)X1 >> 31)) ^ (T0 + 2 * T1 + _expKey[keyCtr++]);

                if (index > 7)
                    index = 0;
            }

            keyCtr = 4;
            Int32ToBytes(X2 ^ _expKey[keyCtr++], Output, OutOffset);
            Int32ToBytes(X3 ^ _expKey[keyCtr++], Output, OutOffset + 4);
            Int32ToBytes(X0 ^ _expKey[keyCtr++], Output, OutOffset + 8);
            Int32ToBytes(X1 ^ _expKey[keyCtr], Output, OutOffset + 12);
        }
        #endregion

        #region Serpent SBox Calculations
        private void SuperBox(int Index, ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            switch (Index)
            {
                case 0:
                    Sb0(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 1:
                    Sb1(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 2:
                    Sb2(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 3:
                    Sb3(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 4:
                    Sb4(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 5:
                    Sb5(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 6:
                    Sb6(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 7:
                    Sb7(ref R0, ref R1, ref R2, ref R3);
                    break;
            }
        }

        private void InverseBox(int Index, ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            switch (Index)
            {
                case 0:
                    Ib0(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 1:
                    Ib1(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 2:
                    Ib2(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 3:
                    Ib3(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 4:
                    Ib4(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 5:
                    Ib5(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 6:
                    Ib6(ref R0, ref R1, ref R2, ref R3);
                    break;
                case 7:
                    Ib7(ref R0, ref R1, ref R2, ref R3);
                    break;
            }
        }

        private void Sb0(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R3;
            Int32 t2 = R2 ^ t1;
            Int32 t3 = R1 ^ t2;
            R3 = (R0 & R3) ^ t3;
            Int32 t4 = R0 ^ (R1 & t1);
            R2 = t3 ^ (R2 | t4);
            R0 = R3 & (t2 ^ t4);
            R1 = (~t2) ^ R0;
            R0 ^= (~t4);
        }

        private void Ib0(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R0 ^ R1;
            Int32 t3 = R3 ^ (t1 | t2);
            Int32 t4 = R2 ^ t3;
            R2 = t2 ^ t4;
            Int32 t5 = t1 ^ (R3 & t2);
            R1 = t3 ^ (R2 & t5);
            R3 = (R0 & t3) ^ (t4 | R1);
            R0 = R3 ^ (t4 ^ t5);
        }

        private void Sb1(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ (~R0);
            Int32 t2 = R2 ^ (R0 | t1);
            R2 = R3 ^ t2;
            Int32 t3 = R1 ^ (R3 | t1);
            Int32 t4 = t1 ^ R2;
            R3 = t4 ^ (t2 & t3);
            Int32 t5 = t2 ^ t3;
            R1 = R3 ^ t5;
            R0 = t2 ^ (t4 & t5);
        }

        private void Ib1(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R3;
            Int32 t2 = R0 ^ (R1 & t1);
            Int32 t3 = t1 ^ t2;
            R3 = R2 ^ t3;
            Int32 t4 = R1 ^ (t1 & t2);
            R1 = t2 ^ (R3 | t4);
            Int32 t5 = ~R1;
            Int32 t6 = R3 ^ t4;
            R0 = t5 ^ t6;
            R2 = t3 ^ (t5 | t6);
        }

        private void Sb2(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R1 ^ R3;
            Int32 t3 = t2 ^ (R2 & t1);
            Int32 t4 = R2 ^ t1;
            Int32 t5 = R1 & (R2 ^ t3);
            Int32 t6 = t4 ^ t5;
            R2 = R0 ^ ((R3 | t5) & (t3 | t4));
            R1 = (t2 ^ t6) ^ (R2 ^ (R3 | t1));
            R0 = t3;
            R3 = t6;
        }

        private void Ib2(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R3;
            Int32 t2 = R0 ^ R2;
            Int32 t3 = R2 ^ t1;
            Int32 t4 = R0 | ~t1;
            R0 = t2 ^ (R1 & t3);
            Int32 t5 = t1 ^ (t2 | (R3 ^ t4));
            Int32 t6 = ~t3;
            Int32 t7 = R0 | t5;
            R1 = t6 ^ t7;
            R2 = (R3 & t6) ^ (t2 ^ t7);
            R3 = t5;
        }

        private void Sb3(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R1;
            Int32 t2 = R0 | R3;
            Int32 t3 = R2 ^ R3;
            Int32 t4 = (R0 & R2) | (t1 & t2);
            R2 = t3 ^ t4;
            Int32 t5 = t4 ^ (R1 ^ t2);
            R0 = t1 ^ (t3 & t5);
            Int32 t6 = R2 & R0;
            R3 = (R1 | R3) ^ (t3 ^ t6);
            R1 = t5 ^ t6;
        }

        private void Ib3(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R2;
            Int32 t2 = R0 ^ (R1 & t1);
            Int32 t3 = R3 | t2;
            Int32 t4 = R3 ^ (t1 | t3);
            R2 = (R2 ^ t2) ^ t4;
            Int32 t5 = (R0 | R1) ^ t4;
            R0 = t1 ^ t3;
            R3 = t2 ^ (R0 & t5);
            R1 = R3 ^ (R0 ^ t5);
        }

        private void Sb4(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R3;
            Int32 t2 = R2 ^ (R3 & t1);
            Int32 t3 = R1 | t2;
            R3 = t1 ^ t3;
            Int32 t4 = ~R1;
            Int32 t5 = t2 ^ (t1 | t4);
            Int32 t6 = t1 ^ t4;
            Int32 t7 = (R0 & t5) ^ (t3 & t6);
            R1 = (R0 ^ t2) ^ (t6 & t7);
            R0 = t5;
            R2 = t7;
        }

        private void Ib4(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ (R0 & (R2 | R3));
            Int32 t2 = R2 ^ (R0 & t1);
            Int32 t3 = R3 ^ t2;
            Int32 t4 = ~R0;
            Int32 t5 = t1 ^ (t2 & t3);
            Int32 t6 = R3 ^ (t3 | t4);
            R1 = t3;
            R0 = t5 ^ t6;
            R2 = (t1 & t6) ^ (t3 ^ t4);
            R3 = t5;
        }

        private void Sb5(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R0 ^ R1;
            Int32 t3 = R0 ^ R3;
            Int32 t4 = (R2 ^ t1) ^ (t2 | t3);
            Int32 t5 = R3 & t4;
            Int32 t6 = t5 ^ (t2 ^ t4);
            Int32 t7 = t3 ^ (t1 | t4);
            R2 = (t2 | t5) ^ t7;
            R3 = (R1 ^ t5) ^ (t6 & t7);
            R0 = t4;
            R1 = t6;
        }

        private void Ib5(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R2;
            Int32 t2 = R3 ^ (R1 & t1);
            Int32 t3 = R0 & t2;
            Int32 t4 = t3 ^ (R1 ^ t1);
            Int32 t5 = R1 | t4;
            Int32 t6 = t2 ^ (R0 & t5);
            Int32 t7 = R0 | R3;
            R2 = (R1 & t7) ^ (t3 | (R0 ^ R2));
            R0 = t7 ^ (t1 ^ t5);
            R1 = t6;
            R3 = t4;
        }

        private void Sb6(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R3;
            Int32 t2 = R1 ^ t1;
            Int32 t3 = R2 ^ (~R0 | t1);
            R1 ^= t3;
            Int32 t4 = t1 | R1;
            Int32 t5 = R3 ^ (t1 | R1);
            R2 = t2 ^ (t3 & t5);
            Int32 t6 = t3 ^ t5;
            R0 = R2 ^ t6;
            R3 = (~t3) ^ (t2 & t6);
        }

        private void Ib6(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R0 ^ R1;
            Int32 t3 = R2 ^ t2;
            Int32 t4 = R3 ^ (R2 | t1);
            Int32 t5 = t3 ^ t4;
            Int32 t6 = t2 ^ (t3 & t4);
            Int32 t7 = t4 ^ (R1 | t6);
            Int32 t8 = R1 | t7;
            R0 = t6 ^ t8;
            R2 = (R3 & t1) ^ (t3 ^ t8);
            R1 = t5;
            R3 = t7;
        }

        private void Sb7(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R2;
            Int32 t2 = R3 ^ (R2 & t1);
            Int32 t3 = R0 ^ t2;
            R1 ^= (t3 & (R3 | t1));
            Int32 t4 = t1 ^ (R0 & t3);
            Int32 t5 = t3 ^ (t2 | R1);
            R2 = t2 ^ (t4 & t5);
            R0 = (~t5) ^ (t4 & R2);
            R3 = t4;
        }

        private void Ib7(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R2 | (R0 & R1);
            Int32 t2 = R3 & (R0 | R1);
            Int32 t3 = t1 ^ t2;
            Int32 t4 = R1 ^ t2;
            R1 = R0 ^ (t4 | (t3 ^ ~R3));
            Int32 t8 = (R2 ^ t4) ^ (R3 | R1);
            R2 = (t1 ^ R1) ^ (t8 ^ (R0 & t3));
            R0 = t8;
            R3 = t3;
        }

        private void InverseTransform(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            // Apply the inverse of the linear transformation to the register set
            Int32 x2 = RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
            Int32 x0 = RotateRight(R0, 5) ^ R1 ^ R3;
            Int32 x3 = RotateRight(R3, 7);
            Int32 x1 = RotateRight(R1, 1);

            R3 = x3 ^ x2 ^ x0 << 3;
            R1 = x1 ^ x0 ^ x2;
            R2 = RotateRight(x2, 3);
            R0 = RotateRight(x0, 13);
        }

        private void LinearTransform(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            // Apply the linear transformation to the register set
            Int32 x0 = RotateLeft(R0, 13);
            Int32 x2 = RotateLeft(R2, 3);
            Int32 x1 = R1 ^ x0 ^ x2;
            Int32 x3 = R3 ^ x2 ^ x0 << 3;

            R1 = RotateLeft(x1, 1);
            R3 = RotateLeft(x3, 7);
            R0 = RotateLeft(x0 ^ R1 ^ R3, 5);
            R2 = RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
        }

        private Int32 RotateLeft(Int32 X, Int32 Bits)
        {
            return ((X << Bits) | (Int32)((UInt32)X >> (32 - Bits)));
        }

        private Int32 RotateRight(Int32 X, Int32 Bits)
        {
            return ((Int32)((UInt32)X >> Bits) | (X << (32 - Bits)));
        }
        #endregion

        #region Helpers
        private Int32 BytesToInt32(byte[] Input, Int32 InOffset)
        {
            return (((byte)(Input[InOffset])) |
                ((byte)(Input[InOffset + 1]) << 8) |
                ((byte)(Input[InOffset + 2]) << 16) |
                ((byte)(Input[InOffset + 3]) << 24));
        }

        private void Int32ToBytes(Int32 Dword, byte[] Output, Int32 OutOffset)
        {
            Output[OutOffset] = (byte)Dword;
            Output[OutOffset + 1] = (byte)(Dword >> 8);
            Output[OutOffset + 2] = (byte)(Dword >> 16);
            Output[OutOffset + 3] = (byte)(Dword >> 24);
        }

        private Int32 Fe0(Int32 X)
        {
            return _sprBox[2 * (byte)X] ^
                _sprBox[2 * (byte)(X >> 8) + 0x001] ^
                _sprBox[2 * (byte)(X >> 16) + 0x200] ^
                _sprBox[2 * (byte)(X >> 24) + 0x201];
        }

        private Int32 Fe3(Int32 X)
        {
            return _sprBox[2 * (byte)(X >> 24)] ^
                _sprBox[2 * (byte)X + 0x001] ^
                _sprBox[2 * (byte)(X >> 8) + 0x200] ^
                _sprBox[2 * (byte)(X >> 16) + 0x201];
        }

        private Int32 LFSR1(Int32 X)
        {
            return (X >> 1) ^
                (((X & 0x01) != 0) ? GF256_FDBK_2 : 0);
        }

        private Int32 LFSR2(Int32 X)
        {
            return (X >> 2) ^
                (((X & 0x02) != 0) ? GF256_FDBK_2 : 0) ^
                (((X & 0x01) != 0) ? GF256_FDBK_4 : 0);
        }

        private Int32 MDSEncode(Int32 K0, Int32 K1)
        {
            Int32 ret = K1;

            for (int i = 0; i < 4; i++)
                ret = RSRem(ret);

            ret ^= K0;

            for (int i = 0; i < 4; i++)
                ret = RSRem(ret);

            return ret;
        }

        private Int32 MX(Int32 X)
        {
            return X ^ LFSR2(X);
        }

        private Int32 MXY(Int32 X)
        {
            return X ^ LFSR1(X) ^ LFSR2(X);
        }

        private Int32 RSRem(Int32 X)
        {
            Int32 b = (Int32)(((UInt32)X >> 24) & 0xff);
            Int32 g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
            Int32 g3 = ((Int32)((UInt32)b >> 1) ^ ((b & 0x01) != 0 ? (Int32)((UInt32)RS_GF_FDBK >> 1) : 0)) ^ g2;

            return ((X << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
        }
        #endregion

        #region Constant Tables
        private static readonly byte[] Q0 = 
        {
            0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
            0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
            0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
            0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
            0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
            0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
            0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
            0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
            0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
            0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
            0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
            0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
            0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
            0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
            0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
            0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0 
        };

        private static readonly byte[] Q1 = 
        { 
            0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
            0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
            0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
            0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
            0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
            0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
            0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
            0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
            0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
            0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
            0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
            0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
            0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
            0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
            0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
            0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91 
        };

        private static readonly Int32[] MDS0 = 
        {
            -1128517003, -320069133, 538985414, -1280062988, -623246373, 33721211, -488494085, -1633748280, 
            -909513654, -724301357, 404253670, 505323371, -1734865339, -1296942979, -1499016472, 640071499, 
            1010587606, -1819047374, -2105348392, 1381144829, 2071712823, -1145358479, 1532729329, 1195869153, 
            606354480, 1364320783, -1162164488, 1246425883, -1077983097, 218984698, -1330597114, 1970658879, 
            -757924514, 2105352378, 1717973422, 976921435, 1499012234, 0, -842165316, 437969053, 
            -1364317075, 2139073473, 724289457, -1094797042, -522149760, -1970663331, 993743570, 1684323029, 
            -656897888, -404249212, 1600120839, 454758676, 741130933, -50547568, 825304876, -2139069021, 
            1936927410, 202146163, 2037997388, 1802191188, 1263207058, 1397975412, -1802203338, -2088558767, 
            707409464, -993747792, 572704957, -707397542, -1111636996, 1212708960, -12702, 1280051094, 
            1094809452, -943200702, -336911113, 471602192, 1566401404, 909517352, 1734852647, -370561140, 
            1145370899, 336915093, -168445028, -808511289, 1061104932, -1061100730, 1920129851, 1414818928, 
            690572490, -252693021, 134807173, -960096309, -202158319, -1936923440, -1532733037, -892692808, 
            1751661478, -1195881085, 943204384, -437965057, -1381149025, 185304183, -926409277, -1717960756, 
            1482222851, 421108335, 235801096, -1785364801, 1886408768, -134795033, 1852755755, 522153698, 
            -1246413447, 151588620, 1633760426, 1465325186, -1616966847, -1650622406, 286352618, 623234489, 
            -1347428892, 1162152090, -538997340, -1549575017, -353708674, 892688602, -303181702, 1128528919, 
            -117912730, -67391084, 926405537, -84262883, -1027446723, -1263219472, 842161630, -1667468877, 
            1448535819, -471606670, -2021171033, 353704732, -101106961, 1667481553, 875866451, -1701149378, 
            -1313783153, 2088554803, -2004313306, 1027450463, -1583228948, -454762634, -2122214358, -1852767927, 
            252705665, -286348664, 370565614, -673746143, -1751648828, -1515870182, -16891925, 1835906521, 
            2021174981, -976917191, 488498585, 1987486925, 1044307117, -875862223, -1229568117, -269526271, 
            303177240, 1616954659, 1785376989, 1296954911, -825300658, -555844563, 1431674361, 2122209864, 
            555856463, 50559730, -1600117147, 1583225230, 1515873912, 1701137244, 1650609752, -33733351, 
            101119117, 1077970661, -218972520, 859024471, 387420263, 84250239, -387424763, 1330609508, 
            -1987482961, 269522275, 1953771446, 168457726, 1549570805, -1684310857, 757936956, 808507045, 
            774785486, 1229556201, 1179021928, 2004309316, -1465329440, -1768553395, 673758531, -1448531607, 
            -640059095, -2038001362, -774797396, -185316843, -1920133799, -690584920, -1179010038, 1111625118, 
            -151600786, 791656519, -572717345, 589510964, -859020747, -235813782, -1044311345, -2054820900, 
            -1886413278, 1903272393, -1869549376, -1431678053, 16904585, -1953766956, 1313770733, -1903267925, 
            -1414815214, 1869561506, -421112819, -606342574, -1835893829, -1212697086, 1768540719, 960092585, 
            -741143337, -1482218655, -1566397154, -1010591308, 1819034704, 117900548, 67403766, 656885442, 
            -1397971178, -791644635, 1347425158, -589498538, -2071717291, -505327351, 2054825406, 320073617
        };

        private static readonly Int32[] MDS1 = 
        {
            -1445381831, 1737496343, -1284399972, -388847962, 67438343, -40349102, -1553629056, 1994384612, 
            -1710734011, -1845343413, -2136940320, 2019973722, -455233617, -575640982, -775986333, 943073834, 
            223667942, -968679392, 895667404, -1732316430, 404623890, -148575253, -321412703, 1819754817, 
            1136470056, 1966259388, 936672123, 647727240, -93319923, 335103044, -1800274949, 1213890174, 
            -226884861, -790328180, -1958234442, 809247780, -2069501977, 1413573483, -553198115, 600137824, 
            424017405, 1537423930, 1030275778, 1494584717, -215880468, -1372494234, -1572966545, -2112465065, 
            1670713360, 22802415, -2092058440, 781289094, -642421395, 1361019779, -1689015638, 2086886749, 
            -1506056088, -348127490, -1512689616, -1104840070, 380087468, 202311945, -483004176, 1629726631, 
            -1057976176, -1934628375, 981507485, -174957476, 1937837068, 740766001, 628543696, 199710294, 
            -1149529454, 1323945678, -1980694271, 1805590046, 1403597876, 1791291889, -1264991293, -241738917, 
            -511490233, -429189096, -1110957534, 1158584472, -496099553, -188107853, -1238403980, 1724643576, 
            -855664231, -1779821548, 65886296, 1459084508, -723416181, 471536917, 514695842, -687025197, 
            -81009950, -1021458232, -1910940066, -1245565908, -376878775, -820854335, -1082223211, -1172275843, 
            -362540783, 2005142283, 963495365, -1351972471, 869366908, -912166543, 1657733119, 1899477947, 
            -2114253041, 2034087349, 156361185, -1378075074, 606945087, -844859786, -107129515, -655457662, 
            -444186560, -978421640, -1177737947, 1292146326, 1146451831, 134876686, -2045554608, -416221193, 
            -1579993289, 490797818, -1439407775, -309572018, 112439472, 1886147668, -1305840781, -766362821, 
            1091280799, 2072707586, -1601644328, 290452467, 828885963, -1035589849, 666920807, -1867186948, 
            539506744, -159448060, 1618495560, -13703707, -1777906612, 1548445029, -1312347349, -1418752370, 
            -1643298238, -1665403403, 1391647707, 468929098, 1604730173, -1822841692, 180140473, -281347591, 
            -1846602989, -2046949368, 1224839569, -295627242, 763158238, 1337073953, -1891454543, 1004237426, 
            1203253039, -2025275457, 1831644846, 1189331136, -698926020, 1048943258, 1764338089, 1685933903, 
            714375553, -834064850, -887634234, 801794409, -54280771, -1755536477, 90106088, 2060512749, 
            -1400385071, 2140013829, -709204892, 447260069, 1270294054, 247054014, -1486846073, 1526257109, 
            673330742, 336665371, 1071543669, 695851481, -2002063634, 1009986861, 1281325433, 45529015, 
            -1198077238, -631753419, -1331903292, 402408259, 1427801220, 536235341, -1977853607, 2100867762, 
            1470903091, -954675249, -1913387514, 1953059667, -1217094757, -990537833, -1621709395, 1926947811, 
            2127948522, 357233908, 580816783, 312650667, 1481532002, 132669279, -1713038051, 876159779, 
            1858205430, 1346661484, -564317646, 1752319558, 1697030304, -1131164211, -620504358, -121193798, 
            -923099490, -1467820330, 735014510, 1079013488, -588544635, -25884150, 847942547, -1534205985, 
            -900978391, 269753372, 561240023, -255019852, -754330412, 1561365130, 266490193, 0, 
            1872369945, -1646257638, 915379348, 1122420679, 1257032137, 1593692882, -1045725313, -522671960
        };

        private static readonly Int32[] MDS2 = 
        {
            -1133134798, -319558623, 549855299, -1275808823, -623126013, 41616011, -486809045, -1631019270, 
            -917845524, -724315127, 417732715, 510336671, -1740269554, -1300385224, -1494702382, 642459319, 
            1020673111, -1825401974, -2099739922, 1392333464, 2067233748, -1150174409, 1542544279, 1205946243, 
            607134780, 1359958498, -1158104378, 1243302643, -1081622712, 234491248, -1341738829, 1967093214, 
            -765537539, 2109373728, 1722705457, 979057315, 1502239004, 0, -843264621, 446503648, 
            -1368543700, 2143387563, 733031367, -1106329927, -528424800, -1973581296, 1003633490, 1691706554, 
            -660547448, -410720347, 1594318824, 454302481, 750070978, -57606988, 824979751, -2136768411, 
            1941074730, 208866433, 2035054943, 1800694593, 1267878658, 1400132457, -1808362353, -2091810017, 
            708323894, -995048292, 582820552, -715467272, -1107509821, 1214269560, -10289202, 1284918279, 
            1097613687, -951924762, -336073948, 470817812, 1568431459, 908604962, 1730635712, -376641105, 
            1142113529, 345314538, -174262853, -808988904, 1059340077, -1069104925, 1916498651, 1416647788, 
            701114700, -253497291, 142936318, -959724009, -216927409, -1932489500, -1533828007, -893859178, 
            1755736123, -1199327155, 941635624, -436214482, -1382044330, 192351108, -926693347, -1714644481, 
            1476614381, 426711450, 235408906, -1782606466, 1883271248, -135792848, 1848340175, 534912878, 
            -1250314947, 151783695, 1638555956, 1468159766, -1623089397, -1657102976, 300552548, 632890829, 
            -1343967267, 1167738120, -542842995, -1550343332, -360781099, 903492952, -310710832, 1125598204, 
            -127469365, -74122319, 933312467, -98698688, -1036139928, -1259293492, 853422685, -1665950607, 
            1443583719, -479009830, -2019063968, 354161947, -101713606, 1674666943, 877868201, -1707173243, 
            -1315983038, 2083749073, -2010740581, 1029651878, -1578327593, -461970209, -2127920748, -1857449727, 
            260116475, -293015894, 384702049, -685648013, -1748723723, -1524980312, -18088385, 1842965941, 
            2026207406, -986069651, 496573925, 1993176740, 1051541212, -885929113, -1232357817, -285085861, 
            303567390, 1612931269, 1792895664, 1293897206, -833696023, -567419268, 1442403741, 2118680154, 
            558834098, 66192250, -1603952602, 1586388505, 1517836902, 1700554059, 1649959502, -48628411, 
            109905652, 1088766086, -224857410, 861352876, 392632208, 92210574, -402266018, 1331974013, 
            -1984984726, 274927765, 1958114351, 184420981, 1559583890, -1682465932, 758918451, 816132310, 
            785264201, 1240025481, 1181238898, 2000975701, -1461671720, -1773300220, 675489981, -1452693207, 
            -651568775, -2043771247, -777203321, -199887798, -1923511019, -693578110, -1190479428, 1117667853, 
            -160500031, 793194424, -572531450, 590619449, -868889502, -244649532, -1043349230, -2049145365, 
            -1893560418, 1909027233, -1866428176, -1432638893, 25756145, -1949004831, 1324174988, -1901359505, 
            -1424839774, 1872916286, -435296684, -615326734, -1833201029, -1224558666, 1764714954, 967391705, 
            -740830452, -1486772445, -1575050579, -1011563623, 1817209924, 117704453, 83231871, 667035462, 
            -1407800153, -802828170, 1350979603, -598287113, -2074770406, -519446191, 2059303461, 328274927
        };

        private static readonly Int32[] MDS3 = 
        {
            -650532391, -1877514352, 1906094961, -760813358, 84345861, -1739391592, 1702929253, -538675489, 
            138779144, 38507010, -1595899744, 1717205094, -575675171, -1335173712, -1083977281, 908736566, 
            1424362836, 1126221379, 1657550178, -1091397442, 504502302, 619444004, -677253929, 2000776311, 
            -1121434691, 851211570, -730122284, -1685576037, 1879964272, -112978951, -1308912463, 1518225498, 
            2047079034, -460533532, 1203145543, 1009004604, -1511553883, 1097552961, 115203846, -983555131, 
            1174214981, -1556456541, 1757560168, 361584917, 569176865, 828812849, 1047503422, 374833686, 
            -1794088043, 1542390107, 1303937869, -1853477231, -1251092043, 528699679, 1403689811, 1667071075, 
            996714043, 1073670975, -701454890, 628801061, -1481894233, 252251151, 904979253, 598171939, 
            -258948880, -1343648593, -2137179520, -1839401582, -2129890431, 657533991, 1993352566, -413791257, 
            2073213819, -372355351, -251557391, -1625396321, -1456188503, -990811452, -1715227495, -1755582057, 
            -2092441213, 1796793963, -937247288, 244860174, 1847583342, -910953271, 796177967, -872913205, 
            -6697729, -367749654, -312998931, -136554761, -510929695, 454368283, -1381884243, 215209740, 
            736295723, 499696413, 425627161, -1037257278, -1991644791, 314691346, 2123743102, 545110560, 
            1678895716, -2079623292, 1841641837, 1787408234, -780389423, -1586378335, -822123826, 935031095, 
            -82869765, 1035303229, 1373702481, -599872036, 759112749, -1535717980, -1655309923, -293414674, 
            -2042567290, -1367816786, -853165619, 76958980, 1433879637, 168691722, 324044307, 821552944, 
            -751328813, 1090133312, 878815796, -1940984436, -1280309581, 1817473132, 712225322, 1379652178, 
            194986251, -1962771573, -1999069048, 1341329743, 1741369703, 1177010758, -1066981440, -1258516300, 
            674766888, 2131031679, 2018009208, 786825006, 122459655, 1264933963, -953437753, 1871620975, 
            222469645, -1141531461, -220507406, -213246989, -1505927258, 1503957849, -1128723780, 989458234, 
            -283930129, -32995842, 26298625, 1628892769, 2094935420, -1306439758, 1118932802, -613270565, 
            -1204861000, 1220511560, 749628716, -473938205, 1463604823, -2053489019, 698968361, 2102355069, 
            -1803474284, 1227804233, 398904087, -899076150, -1010959165, 1554224988, 1592264030, -789742896, 
            -2016301945, -1912242290, -1167796806, -1465574744, -1222227017, -1178726727, 1619502944, -120235272, 
            573974562, 286987281, -562741282, 2044275065, -1427208022, 858602547, 1601784927, -1229520202, 
            -1765099370, 1479924312, -1664831332, -62711812, 444880154, -162717706, 475630108, 951221560, 
            -1405921364, 416270104, -200897036, 1767076969, 1956362100, -174603019, 1454219094, -622628134, 
            -706052395, 1257510218, -1634786658, -1565846878, 1315067982, -396425240, -451044891, 958608441, 
            -1040814399, 1147949124, 1563614813, 1917216882, 648045862, -1815233389, 64674563, -960825146, 
            -90257158, -2099861374, -814863409, 1349533776, -343548693, 1963654773, -1970064758, -1914723187, 
            1277807180, 337383444, 1943478643, -860557108, 164942601, 277503248, -498003998, 0, 
            -1709609062, -535126560, -1886112113, -423148826, -322352404, -36544771, -1417690709, -660021032
        };
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
                    if (_keyEngine != null)
                    {
                        _keyEngine.Dispose();
                        _keyEngine = null;
                    }
                    if (_expKey != null)
                    {
                        Array.Clear(_expKey, 0, _expKey.Length);
                        _expKey = null;
                    }
                    if (_sprBox != null)
                    {
                        Array.Clear(_sprBox, 0, _sprBox.Length);
                        _sprBox = null;
                    }
                    if (_hkdfInfo != null)
                    {
                        Array.Clear(_hkdfInfo, 0, _hkdfInfo.Length);
                        _hkdfInfo = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
