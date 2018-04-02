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
// Portions of this cipher based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <see href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</see>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation based on the Serpent block cipher,
// using HKDF with a selectable Message Digest for expanded key generation.
// Serpent HKDF Extended (SHX)
// Written by John Underhill, November 15, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block
{
    /// <summary>
    /// <h3>SHX: A Serpent cipher extended with an HKDF powered Key Schedule.</h3>
    /// <para>SHX is a Serpent<cite>Serpent</cite> implementation that uses an HKDF generator to expand the user supplied key into a working key integer array.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new SHX()))
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Generator.HKDF">VTDev.Libraries.CEXEngine.Crypto.HKDF Generator</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description><see cref="HKDF">HKDF</see> Digest <see cref="Digests">engine</see> is definable through the <see cref="SHX(int, Digests)">Constructor</see> parameter: KeyEngine.</description></item>
    /// <item><description>Key Schedule is powered by a Hash based Key Derivation Function using a definable <see cref="IDigest">Digest</see>.</description></item>
    /// <item><description>Minimum key size is (IKm + Salt) (N * Digest State Size) + (Digest Hash Size) in bytes.</description></item>
    /// <item><description>Valid block size is 16 bytes wide.</description></item>
    /// <item><description>Valid Rounds assignments are 32, 40, 48, 56, 64, 80, 96 and 128, default is 64.</description></item>
    /// </list>
    /// 
    /// <para>It also takes a user defined number of rounds between 32 (the standard number of rounds), all the way up to 128 rounds in 8 round sets. 
    /// A round count of 40 or 48 is more than sufficient, as theoretical attacks to date are only able to break up to 12 rounds; and would require an enormous amount of memory and processing power.
    /// The transform in SHX is identical to the Serpent implementation SPX, it process rounds by first moving the byte input array into 4 integers, then processing the rounds in a while loop. 
    /// Each round consists of an XOR of each state word (<math>Rn</math>) with a key, an S-Box transformation of those words, and then a linear transformation. 
    /// Each of the 8 S-Boxes are used in succession within a loop cycle. The final round XORs the last 4 keys with the state and shifts them back into the output byte array.</para>
    /// 
    /// <para>The key schedule in SHX powered by an HKDF<cite>RFC 5869</cite> generator, using a Digest HMAC<cite>RFC 2104</cite> (Hash based Message Authentication Code) as its random engine. 
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
    /// SHX is capable of processing up to 128 rounds, that is four times the number of rounds used in a standard implementation of Serpent. 
    /// Valid rounds assignments can be found in the <see cref="LegalRounds"/> static property.</para>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Serpent: <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.</description></item>
    /// <item><description>HMAC: <see href="http://tools.ietf.org/html/rfc2104">RFC 2104</see>.</description></item>
    /// <item><description>Fips: <see href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</see>.</description></item>
    /// <item><description>HKDF: <see href="http://tools.ietf.org/html/rfc5869">RFC 5869</see>.</description></item>
    /// <item><description>NIST: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SHX : IBlockCipher
    {
        #region Constants
        private const string ALG_NAME = "SHX";
        private const Int32 BLOCK_SIZE = 16;
        private const Int32 ROUNDS32 = 32;
        private const Int32 LEGAL_KEYS = 10;
        private const Int32 MAX_ROUNDS = 128;
        private const Int32 MIN_ROUNDS = 32;
        private const Int32 PHI = unchecked((Int32)0x9E3779B9);
        #endregion

        #region Fields
        private Int32 _dfnRounds = 64;
        // configurable nonce can create a unique distribution, can be byte(0)
        private byte[] _hkdfInfo = System.Text.Encoding.ASCII.GetBytes("SHX version 1 information string");
        private IDigest _keyEngine;
        private bool _isDisposed = false;
        private bool _isEncryption;
        private Int32 _ikmSize = 0;
        private Int32[] _expKey;
        private bool _isInitialized = false;
        private int[] _legalKeySizes = new int[LEGAL_KEYS];
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
                    throw new CryptoSymmetricException("SHX:DistributionCode", "Distribution Code can not be null!", new ArgumentNullException());

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
            get { return new int[] { 16, 32 }; }
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
            get { return new int[] { 32, 40, 48, 56, 64, 80, 96, 128 }; }
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
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 32 rounds.</param>
        /// <param name="KeyEngine">The Key Schedule KDF digest engine; can be any one of the <see cref="Digests">Digest</see> implementations. The default engine is <see cref="SHA512"/>.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public SHX(int Rounds = ROUNDS32, Digests KeyEngine = Digests.SHA512)
        {
            if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64 && Rounds != 80 && Rounds != 96 && Rounds != 128)
                throw new CryptoSymmetricException("SHX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64, 80, 96 and 128.", new ArgumentOutOfRangeException());

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
            if (KeyParam.Key.Length < LegalKeySizes[0])
                throw new CryptoSymmetricException("SHX:Initialize", String.Format("Invalid key size! Key must be at least {0}  bytes ({1} bit).", LegalKeySizes[0], LegalKeySizes[0] * 8), new ArgumentOutOfRangeException());
            if ((KeyParam.Key.Length - _keyEngine.DigestSize) % _keyEngine.BlockSize != 0)
                throw new CryptoSymmetricException("SHX:Initialize", String.Format("Invalid key size! Key must be (length - IKm length: {0} bytes) + multiple of {1} block size.", _keyEngine.DigestSize, _keyEngine.BlockSize), new ArgumentOutOfRangeException());

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
            if (_isEncryption)
                Encrypt16(Input, InOffset, Output, OutOffset);
            else
                Decrypt16(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private Int32[] ExpandKey(byte[] Key)
        {
            // expanded key size
            int keySize = 4 * (_dfnRounds + 1);

            // hkdf return array
            int keyBytes = keySize * 4;
            byte[] rawKey = new byte[keyBytes];
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

            // initialize working key
            Int32[] wK = new Int32[keySize];
            // copy bytes to working key
            Buffer.BlockCopy(rawKey, 0, wK, 0, keyBytes);

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
                    throw new CryptoSymmetricException("SHX:GetKeyEngine", "The digest type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region Rounds Processing
        private void Decrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            int keyCtr = _expKey.Length - 1;

            // input round
            Int32 R3 = _expKey[keyCtr--] ^ BytesToInt32(Input, InOffset);
            Int32 R2 = _expKey[keyCtr--] ^ BytesToInt32(Input, InOffset + 4);
            Int32 R1 = _expKey[keyCtr--] ^ BytesToInt32(Input, InOffset + 8);
            Int32 R0 = _expKey[keyCtr--] ^ BytesToInt32(Input, InOffset + 12);

            // process 8 round blocks
            while (keyCtr > 4)
            {
                Ib7(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib6(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib5(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib4(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib3(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib2(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib1(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[keyCtr--];
                R2 ^= _expKey[keyCtr--];
                R1 ^= _expKey[keyCtr--];
                R0 ^= _expKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib0(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr > 4)
                {
                    R3 ^= _expKey[keyCtr--];
                    R2 ^= _expKey[keyCtr--];
                    R1 ^= _expKey[keyCtr--];
                    R0 ^= _expKey[keyCtr--];
                    InverseTransform(ref R0, ref R1, ref R2, ref R3);
                }
            }

            // last round
            Int32ToBytes(R3 ^ _expKey[keyCtr--], Output, OutOffset);
            Int32ToBytes(R2 ^ _expKey[keyCtr--], Output, OutOffset + 4);
            Int32ToBytes(R1 ^ _expKey[keyCtr--], Output, OutOffset + 8);
            Int32ToBytes(R0 ^ _expKey[keyCtr], Output, OutOffset + 12);
        }

        private void Encrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            int keyCtr = 0;

            // input round
            Int32 R0 = BytesToInt32(Input, InOffset + 12);
            Int32 R1 = BytesToInt32(Input, InOffset + 8);
            Int32 R2 = BytesToInt32(Input, InOffset + 4);
            Int32 R3 = BytesToInt32(Input, InOffset);

            // process 8 round blocks
            while (keyCtr < _expKey.Length - 4)
            {
                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb0(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb1(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb2(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3); ;

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb3(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb4(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb5(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb6(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[keyCtr++];
                R1 ^= _expKey[keyCtr++];
                R2 ^= _expKey[keyCtr++];
                R3 ^= _expKey[keyCtr++];
                Sb7(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr < _expKey.Length - 4)
                    LinearTransform(ref R0, ref R1, ref R2, ref R3);
            }

            // last round
            Int32ToBytes(_expKey[keyCtr++] ^ R0, Output, OutOffset + 12);
            Int32ToBytes(_expKey[keyCtr++] ^ R1, Output, OutOffset + 8);
            Int32ToBytes(_expKey[keyCtr++] ^ R2, Output, OutOffset + 4);
            Int32ToBytes(_expKey[keyCtr] ^ R3, Output, OutOffset);
        }
        #endregion

        #region Helpers
        private static Int32 BytesToInt32(byte[] Input, Int32 InOffset)
        {
            return (((byte)(Input[InOffset]) << 24) |
                ((byte)(Input[InOffset + 1]) << 16) |
                ((byte)(Input[InOffset + 2]) << 8) |
                ((byte)(Input[InOffset + 3])));
        }

        private static void Int32ToBytes(Int32 Dword, byte[] Output, Int32 OutOffset)
        {
            Output[OutOffset + 3] = (byte)(Dword);
            Output[OutOffset + 2] = (byte)(Dword >> 8);
            Output[OutOffset + 1] = (byte)(Dword >> 16);
            Output[OutOffset] = (byte)(Dword >> 24);
        }

        private static Int32 RotateLeft(Int32 X, Int32 Bits)
        {
            return ((X << Bits) | (Int32)((UInt32)X >> (32 - Bits)));
        }

        private static Int32 RotateRight(Int32 X, Int32 Bits)
        {
            return ((Int32)((UInt32)X >> Bits) | (X << (32 - Bits)));
        }
        #endregion

        #region SBox Calculations
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

        /// <remarks>
        /// InvSO - {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 } - 15 terms.
        /// </remarks>
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

        /// <remarks>
        /// S1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS1 - { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 } - 14 steps
        /// </remarks>
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

        /// <remarks>
        /// S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS2 - {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 } - 16 steps
        /// </remarks>
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

        /// <remarks>
        /// S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS3 - { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 } - 15 terms
        /// </remarks>
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

        /// <remarks>
        /// S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS4 - { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 } - 15 terms
        /// </remarks>
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

        /// <remarks>
        /// S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS5 - { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 } - 16 terms
        /// </remarks>
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

        /// <remarks>
        /// S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS6 - {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 } - 15 terms
        /// </remarks>
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

        /// <remarks>
        /// S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms
        /// </remarks>
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

        /// <remarks>
        /// InvS7 - { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } - 17 terms
        /// </remarks>
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

        /// <remarks>
        /// Apply the linear transformation to the register set
        /// </remarks>
        private void LinearTransform(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 x0 = RotateLeft(R0, 13);
            Int32 x2 = RotateLeft(R2, 3);
            Int32 x1 = R1 ^ x0 ^ x2;
            Int32 x3 = R3 ^ x2 ^ x0 << 3;

            R1 = RotateLeft(x1, 1);
            R3 = RotateLeft(x3, 7);
            R0 = RotateLeft(x0 ^ R1 ^ R3, 5);
            R2 = RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
        }

        /// <remarks>
        /// Apply the inverse of the linear transformation to the register set
        /// </remarks>
        private void InverseTransform(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 x2 = RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
            Int32 x0 = RotateRight(R0, 5) ^ R1 ^ R3;
            Int32 x3 = RotateRight(R3, 7);
            Int32 x1 = RotateRight(R1, 1);

            R3 = x3 ^ x2 ^ x0 << 3;
            R1 = x1 ^ x0 ^ x2;
            R2 = RotateRight(x2, 3);
            R0 = RotateRight(x0, 13);
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
