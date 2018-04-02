#region Directives
using System;
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
// The Skein Hash Function Family: <see href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</see>.
// Implementation Details:
// An implementation of the Skein digest. 
// Written by John Underhill, January 13, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// <h3>Skein512: An implementation of the Skein digest with a 512 bit digest return size.</h3>
    /// <para>SHA-3 finalist<cite>NIST IR7896</cite>: The Skein<cite>Skein</cite> digest</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new Skein512())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/03/10" version="1.3.0.0">Added Initialize call to Ctor</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Block size is 64 bytes, (512 bits).</description></item>
    /// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods, and resets the internal state.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method does NOT reset the internal state; call <see cref="Reset()"/> to reinitialize.</description></item>
    /// </list> 
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>The Skein Hash Function Family: <see href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</see>.</description></item>
    /// <item><description>Skein <see href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</see> Support for the Skein Hash Family.</description></item>
    /// <item><description>SHA3: <see href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Adapted from the excellent project by Alberto Fajardo: <see href="http://code.google.com/p/skeinfish/">Skeinfish Release 0.50</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Skein512 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "Skein512";
        private const int BLOCK_SIZE = 64;
        private const int DIGEST_SIZE = 64;
        private const int STATE_SIZE = 512;
        #endregion

        #region Fields
        private int _bytesFilled; 
        private Threefish512 _blockCipher;
        private UInt64[] _cipherInput;
        private int _cipherStateBits;
        private int _cipherStateBytes;
        private int _cipherStateWords;
        private byte[] _inputBuffer;
        private bool _isDisposed = false;
        private int _outputBytes;
        private UInt64[] _digestState;
        private int _stateSize;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize 
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// The post-chain configuration value
        /// </summary>
        [CLSCompliant(false)]
        public UInt64[] ConfigValue { get; private set; }

        /// <summary>
        /// The configuration string
        /// </summary>
        [CLSCompliant(false)]
        public UInt64[] ConfigString { get; private set; }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize 
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// The initialization type
        /// </summary>
        public SkeinInitializationType InitializationType { get; private set; }

        /// <summary>
        /// Get: The Digest name
        /// </summary>
        public string Name 
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// State size in bits
        /// </summary>
        public int StateSize
        {
            get { return _cipherStateBits; }
        }

        /// <summary>
        /// Ubi Tweak parameters
        /// </summary>
        public UbiTweak UbiParameters { get; private set; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initializes the Skein hash instance
        /// </summary>
        /// 
        /// <param name="InitializationType">Digest initialization type <see cref="SkeinInitializationType"/></param>
        public Skein512(SkeinInitializationType InitializationType = SkeinInitializationType.Normal)
        {
            this.InitializationType = InitializationType;

            _cipherStateBits = STATE_SIZE;
            _cipherStateBytes = STATE_SIZE / 8;
            _cipherStateWords = STATE_SIZE / 64;
            _outputBytes = (STATE_SIZE + 7) / 8;
            _blockCipher = new Threefish512();

            // Allocate buffers
            _inputBuffer = new byte[_cipherStateBytes];
            _cipherInput = new UInt64[_cipherStateWords];
            _digestState = new UInt64[_cipherStateWords];

            // Allocate tweak
            UbiParameters = new UbiTweak();

            // initialize and enerate the configuration string
            SkeinConfig();
            SetSchema(83, 72, 65, 51); // "SHA3"
            SetVersion(1);
            GenerateConfiguration();
            Initialize(InitializationType);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Skein512()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoHashException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoHashException("Skein512:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            int bytesDone = 0;
            int offset = InOffset;

            // Fill input buffer
            while (bytesDone < Length && offset < Input.Length)
            {
                // Do a transform if the input buffer is filled
                if (_bytesFilled == _cipherStateBytes)
                {
                    // Copy input buffer to cipher input buffer
                    InputBufferToCipherInput();

                    // Process the block
                    ProcessBlock(_cipherStateBytes);

                    // Clear first flag, which will be set
                    // by Initialize() if this is the first transform
                    UbiParameters.IsFirstBlock = false;

                    // Reset buffer fill count
                    _bytesFilled = 0;
                }

                _inputBuffer[_bytesFilled++] = Input[offset++];
                bytesDone++;
            }
        }

        /// <summary>
        /// Get the Hash value.
        /// <para>Note: <see cref="Reset()"/> is called post hash calculation.</para> 
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            byte[] hash = new byte[DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            Reset();

            return hash;
        }

        /// <summary>
        /// <para>Do final processing and get the hash value. 
        /// Note: Digest is not reset after calling DoFinal. 
        /// <see cref="Reset()"/> must be called before a new hash can be generated.</para>
        /// </summary>
        /// 
        /// <param name="Output">The Hash value container</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value</returns>
        /// 
        /// <exception cref="CryptoHashException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < DigestSize)
                throw new CryptoHashException("Skein512:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            int i;

            // Pad left over space in input buffer with zeros and copy to cipher input buffer
            for (i = _bytesFilled; i < _inputBuffer.Length; i++)
                _inputBuffer[i] = 0;

            InputBufferToCipherInput();

            // Do final message block
            UbiParameters.IsFinalBlock = true;
            ProcessBlock(_bytesFilled);

            // Clear cipher input
            for (i = 0; i < _cipherInput.Length; i++)
                _cipherInput[i] = 0;

            // Do output block counter mode output
            int j;

            var hash = new byte[_outputBytes];
            var oldState = new UInt64[_cipherStateWords];

            // Save old state
            for (j = 0; j < _digestState.Length; j++)
                oldState[j] = _digestState[j];

            for (i = 0; i < _outputBytes; i += _cipherStateBytes)
            {
                UbiParameters.StartNewBlockType(UbiType.Out);
                UbiParameters.IsFinalBlock = true;
                ProcessBlock(8);

                // Output a chunk of the hash
                int outputSize = _outputBytes - i;
                if (outputSize > _cipherStateBytes)
                    outputSize = _cipherStateBytes;

                PutBytes(_digestState, hash, i, outputSize);

                // Restore old state
                for (j = 0; j < _digestState.Length; j++)
                    _digestState[j] = oldState[j];

                // Increment counter
                _cipherInput[0]++;
            }

            Buffer.BlockCopy(hash, 0, Output, OutOffset, hash.Length);

            return hash.Length;
        }

        /// <summary>
        /// Used to re-initialize the digest state.
        /// <para>Creates the initial state with zeros instead of the configuration block, then initializes the hash. 
        /// This does not start a new UBI block type, and must be done manually.</para>
        /// </summary>
        /// 
        /// <param name="InitializationType">Initialization parameters</param>
        public void Initialize(SkeinInitializationType InitializationType)
        {
            this.InitializationType = InitializationType;

            switch (InitializationType)
            {
                case SkeinInitializationType.Normal:
                    // Normal initialization
                    Initialize();
                    return;

                case SkeinInitializationType.ZeroedState:
                    // Copy the configuration value to the state
                    for (int i = 0; i < _digestState.Length; i++)
                        _digestState[i] = 0;
                    break;

                case SkeinInitializationType.ChainedState:
                    // Keep the state as it is and do nothing
                    break;

                case SkeinInitializationType.ChainedConfig:
                    // Generate a chained configuration
                    GenerateConfiguration(_digestState);
                    // Continue initialization
                    Initialize();
                    return;
            }

            // Reset bytes filled
            _bytesFilled = 0;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            Initialize(InitializationType);
        }

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            BlockUpdate(new byte[] { Input }, 0, 1);
        }
        #endregion

        #region SkeinConfig
        /// <remarks>
        /// Default configuration
        /// </remarks>
        private void SkeinConfig()
        {
            _stateSize = StateSize;
            // Allocate config value
            ConfigValue = new UInt64[StateSize / 8];
            // Set the state size for the configuration
            ConfigString = new UInt64[ConfigValue.Length];
            ConfigString[1] = (UInt64)DigestSize * 8;
        }

        /// <remarks>
        /// Default generation function
        /// </remarks>
        private void GenerateConfiguration()
        {
            var cipher = new Threefish512();
            var tweak = new UbiTweak();

            // Initialize the tweak value
            tweak.StartNewBlockType(UbiType.Config);
            tweak.IsFinalBlock = true;
            tweak.BitsProcessed = 32;

            cipher.SetTweak(tweak.Tweak);
            cipher.Encrypt(ConfigString, ConfigValue);

            ConfigValue[0] ^= ConfigString[0];
            ConfigValue[1] ^= ConfigString[1];
            ConfigValue[2] ^= ConfigString[2];
        }

        /// <summary>
        /// Generate a configuration using a state key
        /// </summary>
        /// 
        /// <param name="InitialState">Twofish Cipher key</param>
        [CLSCompliant(false)]
        public void GenerateConfiguration(UInt64[] InitialState)
        {
            var cipher = new Threefish512();
            var tweak = new UbiTweak();

            // Initialize the tweak value
            tweak.StartNewBlockType(UbiType.Config);
            tweak.IsFinalBlock = true;
            tweak.BitsProcessed = 32;

            cipher.SetKey(InitialState);
            cipher.SetTweak(tweak.Tweak);
            cipher.Encrypt(ConfigString, ConfigValue);

            ConfigValue[0] ^= ConfigString[0];
            ConfigValue[1] ^= ConfigString[1];
            ConfigValue[2] ^= ConfigString[2];
        }

        /// <summary>
        /// Set the Schema. Schema must be 4 bytes.
        /// </summary>
        /// 
        /// <param name="Schema">Schema Configuration string</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid schema is used</exception>
        public void SetSchema(params byte[] Schema)
        {
            if (Schema.Length != 4)
                throw new CryptoHashException("Skein512:SetSchema", "Schema must be 4 bytes.", new Exception());

            UInt64 n = ConfigString[0];

            // Clear the schema bytes
            n &= ~(UInt64)0xfffffffful;
            // Set schema bytes
            n |= (UInt64)Schema[3] << 24;
            n |= (UInt64)Schema[2] << 16;
            n |= (UInt64)Schema[1] << 8;
            n |= (UInt64)Schema[0];

            ConfigString[0] = n;
        }

        /// <summary>
        /// Set the version string. Version must be between 0 and 3, inclusive.
        /// </summary>
        /// 
        /// <param name="Version">Version string</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid version is used</exception>
        public void SetVersion(int Version)
        {
            if (Version < 0 || Version > 3)
                throw new CryptoHashException("Skein512:SetVersion", "Version must be between 0 and 3, inclusive.", new Exception());

            ConfigString[0] &= ~((UInt64)0x03 << 32);
            ConfigString[0] |= (UInt64)Version << 32;
        }

        /// <summary>
        /// Set the tree leaf size
        /// </summary>
        /// 
        /// <param name="Size">Leaf size</param>
        public void SetTreeLeafSize(byte Size)
        {
            ConfigString[2] &= ~(UInt64)0xff;
            ConfigString[2] |= (UInt64)Size;
        }

        /// <summary>
        /// Set the tree fan out size
        /// </summary>
        /// 
        /// <param name="Size">Fan out size</param>
        public void SetTreeFanOutSize(byte Size)
        {
            ConfigString[2] &= ~((UInt64)0xff << 8);
            ConfigString[2] |= (UInt64)Size << 8;
        }

        /// <summary>
        /// Set the tree height. Tree height must be zero or greater than 1.
        /// </summary>
        /// 
        /// <param name="Height">Tree height</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid tree height is used</exception>
        public void SetMaxTreeHeight(byte Height)
        {
            if (Height == 1)
                throw new CryptoHashException("Skein512:SetMaxTreeHeight", "Tree height must be zero or greater than 1.", new Exception());

            ConfigString[2] &= ~((UInt64)0xff << 16);
            ConfigString[2] |= (UInt64)Height << 16;
        }
        #endregion

        #region Threefish512
        private class Threefish512
        {
            #region Constants
            private const int CipherSize = 512;
            private const int CipherQwords = CipherSize / 64;
            private const int ExpandedKeySize = CipherQwords + 1;
            private const UInt64 KeyScheduleConst = 0x1BD11BDAA9FC1A22;
            private const int ExpandedTweakSize = 3;
            #endregion

            #region Fields
            private UInt64[] _expandedKey;
            private UInt64[] _expandedTweak;
            #endregion

            #region Constructor
            internal Threefish512()
            {
                // Create the expanded key array
                _expandedTweak = new UInt64[ExpandedTweakSize];
                _expandedKey = new UInt64[ExpandedKeySize];
                _expandedKey[ExpandedKeySize - 1] = KeyScheduleConst;
            }
            #endregion

            #region Internal Methods
            internal void Clear()
            {
                if (_expandedKey != null)
                {
                    Array.Clear(_expandedKey, 0, _expandedKey.Length);
                    _expandedKey = null;
                }
                if (_expandedTweak != null)
                {
                    Array.Clear(_expandedTweak, 0, _expandedTweak.Length);
                    _expandedTweak = null;
                }
            }

            internal void Encrypt(UInt64[] Input, UInt64[] Output)
            {
                // Cache the block, key, and tweak
                UInt64 B0 = Input[0], B1 = Input[1],
                      B2 = Input[2], B3 = Input[3],
                      B4 = Input[4], B5 = Input[5],
                      B6 = Input[6], B7 = Input[7];
                UInt64 K0 = _expandedKey[0], K1 = _expandedKey[1],
                      K2 = _expandedKey[2], K3 = _expandedKey[3],
                      K4 = _expandedKey[4], K5 = _expandedKey[5],
                      K6 = _expandedKey[6], K7 = _expandedKey[7],
                      K8 = _expandedKey[8];
                UInt64 T0 = _expandedTweak[0], T1 = _expandedTweak[1],
                      T2 = _expandedTweak[2];

                Mix(ref B0, ref B1, 46, K0, K1);
                Mix(ref B2, ref B3, 36, K2, K3);
                Mix(ref B4, ref B5, 19, K4, K5 + T0);
                Mix(ref B6, ref B7, 37, K6 + T1, K7);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K1, K2);
                Mix(ref B2, ref B3, 30, K3, K4);
                Mix(ref B4, ref B5, 34, K5, K6 + T1);
                Mix(ref B6, ref B7, 24, K7 + T2, K8 + 1);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K2, K3);
                Mix(ref B2, ref B3, 36, K4, K5);
                Mix(ref B4, ref B5, 19, K6, K7 + T2);
                Mix(ref B6, ref B7, 37, K8 + T0, K0 + 2);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K3, K4);
                Mix(ref B2, ref B3, 30, K5, K6);
                Mix(ref B4, ref B5, 34, K7, K8 + T0);
                Mix(ref B6, ref B7, 24, K0 + T1, K1 + 3);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K4, K5);
                Mix(ref B2, ref B3, 36, K6, K7);
                Mix(ref B4, ref B5, 19, K8, K0 + T1);
                Mix(ref B6, ref B7, 37, K1 + T2, K2 + 4);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K5, K6);
                Mix(ref B2, ref B3, 30, K7, K8);
                Mix(ref B4, ref B5, 34, K0, K1 + T2);
                Mix(ref B6, ref B7, 24, K2 + T0, K3 + 5);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K6, K7);
                Mix(ref B2, ref B3, 36, K8, K0);
                Mix(ref B4, ref B5, 19, K1, K2 + T0);
                Mix(ref B6, ref B7, 37, K3 + T1, K4 + 6);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K7, K8);
                Mix(ref B2, ref B3, 30, K0, K1);
                Mix(ref B4, ref B5, 34, K2, K3 + T1);
                Mix(ref B6, ref B7, 24, K4 + T2, K5 + 7);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K8, K0);
                Mix(ref B2, ref B3, 36, K1, K2);
                Mix(ref B4, ref B5, 19, K3, K4 + T2);
                Mix(ref B6, ref B7, 37, K5 + T0, K6 + 8);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K0, K1);
                Mix(ref B2, ref B3, 30, K2, K3);
                Mix(ref B4, ref B5, 34, K4, K5 + T0);
                Mix(ref B6, ref B7, 24, K6 + T1, K7 + 9);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K1, K2);
                Mix(ref B2, ref B3, 36, K3, K4);
                Mix(ref B4, ref B5, 19, K5, K6 + T1);
                Mix(ref B6, ref B7, 37, K7 + T2, K8 + 10);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K2, K3);
                Mix(ref B2, ref B3, 30, K4, K5);
                Mix(ref B4, ref B5, 34, K6, K7 + T2);
                Mix(ref B6, ref B7, 24, K8 + T0, K0 + 11);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K3, K4);
                Mix(ref B2, ref B3, 36, K5, K6);
                Mix(ref B4, ref B5, 19, K7, K8 + T0);
                Mix(ref B6, ref B7, 37, K0 + T1, K1 + 12);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K4, K5);
                Mix(ref B2, ref B3, 30, K6, K7);
                Mix(ref B4, ref B5, 34, K8, K0 + T1);
                Mix(ref B6, ref B7, 24, K1 + T2, K2 + 13);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K5, K6);
                Mix(ref B2, ref B3, 36, K7, K8);
                Mix(ref B4, ref B5, 19, K0, K1 + T2);
                Mix(ref B6, ref B7, 37, K2 + T0, K3 + 14);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K6, K7);
                Mix(ref B2, ref B3, 30, K8, K0);
                Mix(ref B4, ref B5, 34, K1, K2 + T0);
                Mix(ref B6, ref B7, 24, K3 + T1, K4 + 15);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);
                Mix(ref B0, ref B1, 46, K7, K8);
                Mix(ref B2, ref B3, 36, K0, K1);
                Mix(ref B4, ref B5, 19, K2, K3 + T1);
                Mix(ref B6, ref B7, 37, K4 + T2, K5 + 16);
                Mix(ref B2, ref B1, 33);
                Mix(ref B4, ref B7, 27);
                Mix(ref B6, ref B5, 14);
                Mix(ref B0, ref B3, 42);
                Mix(ref B4, ref B1, 17);
                Mix(ref B6, ref B3, 49);
                Mix(ref B0, ref B5, 36);
                Mix(ref B2, ref B7, 39);
                Mix(ref B6, ref B1, 44);
                Mix(ref B0, ref B7, 9);
                Mix(ref B2, ref B5, 54);
                Mix(ref B4, ref B3, 56);
                Mix(ref B0, ref B1, 39, K8, K0);
                Mix(ref B2, ref B3, 30, K1, K2);
                Mix(ref B4, ref B5, 34, K3, K4 + T2);
                Mix(ref B6, ref B7, 24, K5 + T0, K6 + 17);
                Mix(ref B2, ref B1, 13);
                Mix(ref B4, ref B7, 50);
                Mix(ref B6, ref B5, 10);
                Mix(ref B0, ref B3, 17);
                Mix(ref B4, ref B1, 25);
                Mix(ref B6, ref B3, 29);
                Mix(ref B0, ref B5, 39);
                Mix(ref B2, ref B7, 43);
                Mix(ref B6, ref B1, 8);
                Mix(ref B0, ref B7, 35);
                Mix(ref B2, ref B5, 56);
                Mix(ref B4, ref B3, 22);

                // Final key schedule
                Output[0] = B0 + K0;
                Output[1] = B1 + K1;
                Output[2] = B2 + K2;
                Output[3] = B3 + K3;
                Output[4] = B4 + K4;
                Output[5] = B5 + K5 + T0;
                Output[6] = B6 + K6 + T1;
                Output[7] = B7 + K7 + 18;
            }

            internal void Decrypt(UInt64[] Input, UInt64[] Output)
            {
                // Cache the block, key, and tweak
                UInt64 B0 = Input[0], B1 = Input[1],
                      B2 = Input[2], B3 = Input[3],
                      B4 = Input[4], B5 = Input[5],
                      B6 = Input[6], B7 = Input[7];
                UInt64 K0 = _expandedKey[0], K1 = _expandedKey[1],
                      K2 = _expandedKey[2], K3 = _expandedKey[3],
                      K4 = _expandedKey[4], K5 = _expandedKey[5],
                      K6 = _expandedKey[6], K7 = _expandedKey[7],
                      K8 = _expandedKey[8];
                UInt64 T0 = _expandedTweak[0], T1 = _expandedTweak[1],
                      T2 = _expandedTweak[2];


                B0 -= K0;
                B1 -= K1;
                B2 -= K2;
                B3 -= K3;
                B4 -= K4;
                B5 -= K5 + T0;
                B6 -= K6 + T1;
                B7 -= K7 + 18;
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K5 + T0, K6 + 17);
                UnMix(ref B4, ref B5, 34, K3, K4 + T2);
                UnMix(ref B2, ref B3, 30, K1, K2);
                UnMix(ref B0, ref B1, 39, K8, K0);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K4 + T2, K5 + 16);
                UnMix(ref B4, ref B5, 19, K2, K3 + T1);
                UnMix(ref B2, ref B3, 36, K0, K1);
                UnMix(ref B0, ref B1, 46, K7, K8);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K3 + T1, K4 + 15);
                UnMix(ref B4, ref B5, 34, K1, K2 + T0);
                UnMix(ref B2, ref B3, 30, K8, K0);
                UnMix(ref B0, ref B1, 39, K6, K7);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K2 + T0, K3 + 14);
                UnMix(ref B4, ref B5, 19, K0, K1 + T2);
                UnMix(ref B2, ref B3, 36, K7, K8);
                UnMix(ref B0, ref B1, 46, K5, K6);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K1 + T2, K2 + 13);
                UnMix(ref B4, ref B5, 34, K8, K0 + T1);
                UnMix(ref B2, ref B3, 30, K6, K7);
                UnMix(ref B0, ref B1, 39, K4, K5);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K0 + T1, K1 + 12);
                UnMix(ref B4, ref B5, 19, K7, K8 + T0);
                UnMix(ref B2, ref B3, 36, K5, K6);
                UnMix(ref B0, ref B1, 46, K3, K4);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K8 + T0, K0 + 11);
                UnMix(ref B4, ref B5, 34, K6, K7 + T2);
                UnMix(ref B2, ref B3, 30, K4, K5);
                UnMix(ref B0, ref B1, 39, K2, K3);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K7 + T2, K8 + 10);
                UnMix(ref B4, ref B5, 19, K5, K6 + T1);
                UnMix(ref B2, ref B3, 36, K3, K4);
                UnMix(ref B0, ref B1, 46, K1, K2);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K6 + T1, K7 + 9);
                UnMix(ref B4, ref B5, 34, K4, K5 + T0);
                UnMix(ref B2, ref B3, 30, K2, K3);
                UnMix(ref B0, ref B1, 39, K0, K1);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K5 + T0, K6 + 8);
                UnMix(ref B4, ref B5, 19, K3, K4 + T2);
                UnMix(ref B2, ref B3, 36, K1, K2);
                UnMix(ref B0, ref B1, 46, K8, K0);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K4 + T2, K5 + 7);
                UnMix(ref B4, ref B5, 34, K2, K3 + T1);
                UnMix(ref B2, ref B3, 30, K0, K1);
                UnMix(ref B0, ref B1, 39, K7, K8);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K3 + T1, K4 + 6);
                UnMix(ref B4, ref B5, 19, K1, K2 + T0);
                UnMix(ref B2, ref B3, 36, K8, K0);
                UnMix(ref B0, ref B1, 46, K6, K7);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K2 + T0, K3 + 5);
                UnMix(ref B4, ref B5, 34, K0, K1 + T2);
                UnMix(ref B2, ref B3, 30, K7, K8);
                UnMix(ref B0, ref B1, 39, K5, K6);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K1 + T2, K2 + 4);
                UnMix(ref B4, ref B5, 19, K8, K0 + T1);
                UnMix(ref B2, ref B3, 36, K6, K7);
                UnMix(ref B0, ref B1, 46, K4, K5);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K0 + T1, K1 + 3);
                UnMix(ref B4, ref B5, 34, K7, K8 + T0);
                UnMix(ref B2, ref B3, 30, K5, K6);
                UnMix(ref B0, ref B1, 39, K3, K4);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K8 + T0, K0 + 2);
                UnMix(ref B4, ref B5, 19, K6, K7 + T2);
                UnMix(ref B2, ref B3, 36, K4, K5);
                UnMix(ref B0, ref B1, 46, K2, K3);
                UnMix(ref B4, ref B3, 22);
                UnMix(ref B2, ref B5, 56);
                UnMix(ref B0, ref B7, 35);
                UnMix(ref B6, ref B1, 8);
                UnMix(ref B2, ref B7, 43);
                UnMix(ref B0, ref B5, 39);
                UnMix(ref B6, ref B3, 29);
                UnMix(ref B4, ref B1, 25);
                UnMix(ref B0, ref B3, 17);
                UnMix(ref B6, ref B5, 10);
                UnMix(ref B4, ref B7, 50);
                UnMix(ref B2, ref B1, 13);
                UnMix(ref B6, ref B7, 24, K7 + T2, K8 + 1);
                UnMix(ref B4, ref B5, 34, K5, K6 + T1);
                UnMix(ref B2, ref B3, 30, K3, K4);
                UnMix(ref B0, ref B1, 39, K1, K2);
                UnMix(ref B4, ref B3, 56);
                UnMix(ref B2, ref B5, 54);
                UnMix(ref B0, ref B7, 9);
                UnMix(ref B6, ref B1, 44);
                UnMix(ref B2, ref B7, 39);
                UnMix(ref B0, ref B5, 36);
                UnMix(ref B6, ref B3, 49);
                UnMix(ref B4, ref B1, 17);
                UnMix(ref B0, ref B3, 42);
                UnMix(ref B6, ref B5, 14);
                UnMix(ref B4, ref B7, 27);
                UnMix(ref B2, ref B1, 33);
                UnMix(ref B6, ref B7, 37, K6 + T1, K7);
                UnMix(ref B4, ref B5, 19, K4, K5 + T0);
                UnMix(ref B2, ref B3, 36, K2, K3);
                UnMix(ref B0, ref B1, 46, K0, K1);

                Output[7] = B7;
                Output[6] = B6;
                Output[5] = B5;
                Output[4] = B4;
                Output[3] = B3;
                Output[2] = B2;
                Output[1] = B1;
                Output[0] = B0;
            }
            #endregion

            #region Private Methods
            private static UInt64 RotateLeft64(UInt64 V, int B)
            {
                return (V << B) | (V >> (64 - B));
            }

            private static UInt64 RotateRight64(UInt64 V, int B)
            {
                return (V >> B) | (V << (64 - B));
            }

            private static void Mix(ref UInt64 A, ref UInt64 B, int R)
            {
                A += B;
                B = RotateLeft64(B, R) ^ A;
            }

            private static void Mix(ref UInt64 A, ref UInt64 B, int R, UInt64 K0, UInt64 K1)
            {
                B += K1;
                A += B + K0;
                B = RotateLeft64(B, R) ^ A;
            }

            private static void UnMix(ref UInt64 A, ref UInt64 B, int R)
            {
                B = RotateRight64(B ^ A, R);
                A -= B;
            }

            private static void UnMix(ref UInt64 A, ref UInt64 B, int R, UInt64 K0, UInt64 K1)
            {
                B = RotateRight64(B ^ A, R);
                A -= B + K0;
                B -= K1;
            }

            internal void SetTweak(UInt64[] Tweak)
            {
                _expandedTweak[0] = Tweak[0];
                _expandedTweak[1] = Tweak[1];
                _expandedTweak[2] = Tweak[0] ^ Tweak[1];
            }

            internal void SetKey(UInt64[] Key)
            {
                int i;
                UInt64 parity = KeyScheduleConst;

                for (i = 0; i < _expandedKey.Length - 1; i++)
                {
                    _expandedKey[i] = Key[i];
                    parity ^= Key[i];
                }

                _expandedKey[i] = parity;
            }
            #endregion
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            // Copy the configuration value to the state
            for (int i = 0; i < _digestState.Length; i++)
                _digestState[i] = ConfigValue[i];

            // Set up tweak for message block
            UbiParameters.StartNewBlockType(UbiType.Message);

            // Reset bytes filled
            _bytesFilled = 0;
        }

        // Moves the byte input buffer to the UInt64 cipher input
        private void InputBufferToCipherInput()
        {
            for (int i = 0; i < _cipherStateWords; i++)
                _cipherInput[i] = BytesToUInt64(_inputBuffer, i * 8);
        }

        private void ProcessBlock(int bytes)
        {
            // Set the key to the current state
            _blockCipher.SetKey(_digestState);

            // Update tweak
            UbiParameters.BitsProcessed += (Int64)bytes;
            _blockCipher.SetTweak(UbiParameters.Tweak);

            // Encrypt block
            _blockCipher.Encrypt(_cipherInput, _digestState);

            // Feed-forward input with state
            for (int i = 0; i < _cipherInput.Length; i++)
                _digestState[i] ^= _cipherInput[i];
        }

        private static UInt64 BytesToUInt64(byte[] Input, int InOffset)
        {
            UInt64 n = Input[InOffset];
            n |= (UInt64)Input[InOffset + 1] << 8;
            n |= (UInt64)Input[InOffset + 2] << 16;
            n |= (UInt64)Input[InOffset + 3] << 24;
            n |= (UInt64)Input[InOffset + 4] << 32;
            n |= (UInt64)Input[InOffset + 5] << 40;
            n |= (UInt64)Input[InOffset + 6] << 48;
            n |= (UInt64)Input[InOffset + 7] << 56;
            return n;
        }

        private static void PutBytes(UInt64[] Input, byte[] Output, int Offset, int ByteCount)
        {
            int j = 0;
            for (int i = 0; i < ByteCount; i++)
            {
                Output[Offset + i] = (byte)((Input[i / 8] >> j) & 0xff);
                j = (j + 8) % 64;
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
                    if (_blockCipher != null)
                    {
                        _blockCipher.Clear();
                        _blockCipher = null;
                    }
                    if (_cipherInput != null)
                    {
                        Array.Clear(_cipherInput, 0, _cipherInput.Length);
                        _cipherInput = null;
                    }
                    if (_digestState != null)
                    {
                        Array.Clear(_digestState, 0, _digestState.Length);
                        _digestState = null;
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
