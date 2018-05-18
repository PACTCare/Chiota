#region Directives
using System;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
// The Skein Hash Function Family: <a href="https://www.schneier.com/skein1.3.pdf">Skein V1.1</a>.
// Implementation Details:
// An implementation of the Skein digest. 
// Written by John Underhill, January 13, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// Specifies the Skein initialization type.
    /// </summary>
    public enum SkeinInitializationType
    {
        /// <summary>
        /// Identical to the standard Skein initialization.
        /// </summary>
        Normal = 0,
        /// <summary>
        /// Creates the initial state with zeros instead of the configuration block, then initializes the hash.
        /// This does not start a new UBI block type, and must be done manually.
        /// </summary>
        ZeroedState = 1,
        /// <summary>
        /// Leaves the initial state set to its previous value, which is then chained with subsequent block transforms.
        /// This does not start a new UBI block type, and must be done manually.
        /// </summary>
        ChainedState = 2,
        /// <summary>
        /// Creates the initial state by chaining the previous state value with the config block, then initializes the hash.
        /// This starts a new UBI block type with the standard Payload type.
        /// </summary>
        ChainedConfig = 3
    }

    #region UbiTweak
    /// <summary>
    /// The Unique Block Iteration (UBI) options
    /// </summary>
    public enum UbiType : long
    {
        /// <summary>
        /// A key that turns Skein into a MAC or KDF function.
        /// </summary>
        Key = 0,
        /// <summary>
        /// The configuration block.
        /// </summary>
        Config = 4,
        /// <summary>
        /// A string that applications can use to create different functions for different uses.
        /// </summary>
        Personalization = 8,
        /// <summary>
        /// Used to hash the public key when hashing a message for signing.
        /// </summary>
        PublicKey = 12,
        /// <summary>
        /// Used for key derivation.
        /// </summary>
        KeyIdentifier = 16,
        /// <summary>
        /// Nonce value for use in stream cipher mode and randomized hashing.
        /// </summary>
        Nonce = 20,
        /// <summary>
        /// The normal message input of the hash function.
        /// </summary>
        Message = 48,
        /// <summary>
        /// The output transform.
        /// </summary>
        Out = 63
    }

    /// <summary>
    /// <para>The Unique Block Iteration (UBI) implementations, <a href="https://www.schneier.com/skein1.3.pdf">section 2.3</a>.</para>
    /// </summary>
    public class UbiTweak
    {
        private const ulong T1FlagFinal = unchecked((ulong)1 << 63);
        private const ulong T1FlagFirst = unchecked((ulong)1 << 62);

        private ulong[] _tweak;

        /// <summary>
        /// Initialize this class
        /// </summary>
        public UbiTweak()
        {
            _tweak = new ulong[2];
        }

        /// <summary>
        /// Gets or sets the number of bits processed so far, inclusive.
        /// </summary>
        public long BitsProcessed
        {
            get { return (long)_tweak[0]; }
            set { _tweak[0] = (ulong)value; }
        }

        /// <summary>
        /// Gets or sets the current UBI block type.
        /// </summary>
        public UbiType BlockType
        {
            get { return (UbiType)(_tweak[1] >> 56); }
            set { _tweak[1] = (ulong)value << 56; }
        }

        /// <summary>
        /// Gets or sets the first block flag.
        /// </summary>
        public bool IsFirstBlock
        {
            get { return (_tweak[1] & T1FlagFirst) != 0; }
            set
            {
                long mask = value ? 1 : 0;
                _tweak[1] = (_tweak[1] & ~T1FlagFirst) | ((ulong)-mask & T1FlagFirst);
            }
        }

        /// <summary>
        /// Gets or sets the final block flag.
        /// </summary>
        public bool IsFinalBlock
        {
            get { return (_tweak[1] & T1FlagFinal) != 0; }
            set
            {
                long mask = value ? 1 : 0;
                _tweak[1] = (_tweak[1] & ~T1FlagFinal) | ((ulong)-mask & T1FlagFinal);
            }
        }

        /// <summary>
        /// Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type.
        /// </summary>
        /// <param name="type">The UBI block type of the new block</param>
        public void StartNewBlockType(UbiType type)
        {
            BitsProcessed = 0;
            BlockType = type;
            IsFirstBlock = true;
        }

        /// <summary>
        /// Gets or sets the current tree level.
        /// </summary>
        public byte TreeLevel
        {
            get { return (byte)((_tweak[1] >> 48) & 0x3f); }
            set
            {
                if (value > 63)
                    throw new CryptoHashException("Skein:TreeLevel", "Tree level must be between 0 and 63, inclusive.", new Exception());

                _tweak[1] &= ~((ulong)0x3f << 48);
                _tweak[1] |= (ulong)value << 48;
            }
        }

        /// <summary>
        /// The current Threefish tweak value.
        /// </summary>
        [CLSCompliant(false)]
        public ulong[] Tweak 
        {
            get { return _tweak; }
            private set { _tweak = value; }
        }
    }
    #endregion

    /// <summary>
    /// Skein256: An implementation of the Skein digest with a 256 bit digest return size
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new Skein256())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Block size is 32 bytes, (256 bits).</description></item>
    /// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods, and resets the internal state.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method does NOT reset the internal state; call <see cref="Reset()"/> to reinitialize.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
    /// <item><description>The Skein Hash Function Family <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</a>.</description></item>
    /// <item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
    /// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition>.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Adapted from the excellent project by Alberto Fajardo: <a href="http://code.google.com/p/skeinfish/">Skeinfish Release 0.50</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Skein256 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "Skein256";
        private const int BLOCK_SIZE = 32;
        private const int DIGEST_SIZE = 32;
        private const int STATE_SIZE = 256;
        private const int STATE_BYTES = STATE_SIZE / 8;
		private const int STATE_WORDS = STATE_SIZE / 64;
        private const int STATE_OUTPUT = (STATE_SIZE + 7) / 8;
        #endregion

        #region Fields
        private Threefish256 m_blockCipher;
        private int m_bytesFilled; 
        private ulong[] m_cipherInput;
        private ulong[] m_configString;
        private ulong[] m_configValue;
        private ulong[] m_digestState;
        private byte[] m_inputBuffer;
        private SkeinInitializationType m_initializationType;
        private bool m_isDisposed = false;
        private int m_outputBytes;
        private UbiTweak m_ubiParameters;
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
        public ulong[] ConfigValue 
        {
            get { return m_configValue; }
            private set { m_configValue = value; }
        }

        /// <summary>
        /// The pre-chain configuration string
        /// </summary>
        [CLSCompliant(false)]
        public ulong[] ConfigString 
        {
            get { return m_configString; }
            private set { m_configString = value; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize 
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// Get: The digests type name
        /// </summary>
        public Digests Enumeral
        {
            get { return Digests.Skein256; }
        }

        /// <summary>
        /// The initialization type
        /// </summary>
        public SkeinInitializationType InitializationType 
        {
            get { return m_initializationType; }
            private set { m_initializationType = value; }
        }

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
            get { return STATE_SIZE; }
        }

        /// <summary>
        /// Ubi Tweak parameters
        /// </summary>
        public UbiTweak UbiParameters 
        {
            get { return m_ubiParameters; }
            private set { m_ubiParameters = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initializes the Skein hash instance.
        /// </summary>
        /// 
        /// <param name="InitializationType">Digest initialization type <see cref="SkeinInitializationType"/></param>
        public Skein256(SkeinInitializationType InitializationType = SkeinInitializationType.Normal)
        {
            m_initializationType = InitializationType;
            m_outputBytes = (STATE_SIZE + 7) / 8;
            m_blockCipher = new Threefish256();
            // allocate buffers
            m_inputBuffer = new byte[STATE_BYTES];
            m_cipherInput = new ulong[STATE_WORDS];
            m_digestState = new ulong[STATE_WORDS];
            // allocate tweak
            m_ubiParameters = new UbiTweak();
            // generate the configuration string
            // allocate config value
            m_configValue = new ulong[STATE_BYTES];
            // set the state size for the configuration
            m_configString = new ulong[STATE_BYTES];
            m_configString[1] = (ulong)DigestSize * 8;

            SetSchema(83, 72, 65, 51); // "SHA3"
            SetVersion(1);
            GenerateConfiguration();
            Initialize(InitializationType);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Skein256()
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
                throw new CryptoHashException("Skein256:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            int bytesDone = 0;
            int offset = InOffset;

            // fill input buffer
            while (bytesDone < Length && offset < Input.Length)
            {
                // do a transform if the input buffer is filled
                if (m_bytesFilled == STATE_BYTES)
                {
                    // copy input buffer to cipher input buffer
                    for (int i = 0; i < STATE_WORDS; i++)
                        m_cipherInput[i] = BytesToUInt64(m_inputBuffer, i * 8);

                    // process the block
                    ProcessBlock(STATE_BYTES);
                    // clear first flag, which will be set by Initialize() if this is the first transform
                    m_ubiParameters.IsFirstBlock = false;
                    // reset buffer fill count
                    m_bytesFilled = 0;
                }

                m_inputBuffer[m_bytesFilled++] = Input[offset++];
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
                throw new CryptoHashException("Skein256:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            // pad left over space in input buffer with zeros
            for (int i = m_bytesFilled; i < m_inputBuffer.Length; i++)
                m_inputBuffer[i] = 0;
            // copy to cipher input buffer
            for (int i = 0; i < STATE_WORDS; i++)
                m_cipherInput[i] = BytesToUInt64(m_inputBuffer, i * 8);

            // do final message block
            m_ubiParameters.IsFinalBlock = true;
            ProcessBlock(m_bytesFilled);

            // clear cipher input
            Array.Clear(m_cipherInput, 0, m_cipherInput.Length);
            // do output block counter mode output
            byte[] hash = new byte[m_outputBytes];
            ulong[] oldState = new ulong[STATE_WORDS];
            // save old state
            Array.Copy(m_digestState, oldState, m_digestState.Length);

            for (int i = 0; i < m_outputBytes; i += STATE_BYTES)
            {
                m_ubiParameters.StartNewBlockType(UbiType.Out);
                m_ubiParameters.IsFinalBlock = true;
                ProcessBlock(8);

                // output a chunk of the hash
                int outputSize = m_outputBytes - i;
                if (outputSize > STATE_BYTES)
                    outputSize = STATE_BYTES;

                PutBytes(m_digestState, hash, i, outputSize);
                // restore old state
                Array.Copy(oldState, m_digestState, oldState.Length);
                // increment counter
                m_cipherInput[0]++;
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
                    {
                        // normal initialization
                        Initialize();
                    }
                    return;
                case SkeinInitializationType.ZeroedState:
                    {
                        // copy the configuration value to the state
                        for (int i = 0; i < m_digestState.Length; i++)
                            m_digestState[i] = 0;
                    }
                    break;
                case SkeinInitializationType.ChainedConfig:
                    {
                        // generate a chained configuration
                        GenerateConfiguration(m_digestState);
                        // continue initialization
                        Initialize();
                    }
                    return;
                case SkeinInitializationType.ChainedState:
                    // keep the state as it is and do nothing
                    break;
            }

            // reset bytes filled
            m_bytesFilled = 0;
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
        /// Default generation function
        /// </remarks>
        private void GenerateConfiguration()
        {
            Threefish256 cipher = new Threefish256();
            UbiTweak tweak = new UbiTweak();

            // initialize the tweak value
            tweak.StartNewBlockType(UbiType.Config);
            tweak.IsFinalBlock = true;
            tweak.BitsProcessed = 32;

            cipher.SetTweak(tweak.Tweak);
            cipher.Encrypt(m_configString, m_configValue);

            m_configValue[0] ^= m_configString[0];
            m_configValue[1] ^= m_configString[1];
            m_configValue[2] ^= m_configString[2];
        }

        /// <summary>
        /// Generate a configuration using a state key
        /// </summary>
        /// 
        /// <param name="InitialState">Twofish Cipher key</param>
        [CLSCompliant(false)]
        public void GenerateConfiguration(ulong[] InitialState)
        {
            Threefish256 cipher = new Threefish256();
            UbiTweak tweak = new UbiTweak();

            // initialize the tweak value
            tweak.StartNewBlockType(UbiType.Config);
            tweak.IsFinalBlock = true;
            tweak.BitsProcessed = 32;

            cipher.SetKey(InitialState);
            cipher.SetTweak(tweak.Tweak);
            cipher.Encrypt(m_configString, m_configValue);

            m_configValue[0] ^= m_configString[0];
            m_configValue[1] ^= m_configString[1];
            m_configValue[2] ^= m_configString[2];
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
                throw new CryptoHashException("Skein256:SetSchema", "Schema must be 4 bytes.", new Exception());

            ulong n = m_configString[0];

            // clear the schema bytes
            n &= ~(ulong)0xfffffffful;
            // set schema bytes
            n |= (ulong)Schema[3] << 24;
            n |= (ulong)Schema[2] << 16;
            n |= (ulong)Schema[1] << 8;
            n |= (ulong)Schema[0];

            m_configString[0] = n;
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
                throw new CryptoHashException("Skein256:SetVersion", "Version must be between 0 and 3, inclusive.", new Exception());

            m_configString[0] &= ~((ulong)0x03 << 32);
            m_configString[0] |= (ulong)Version << 32;
        }

        /// <summary>
        /// Set the tree leaf size
        /// </summary>
        /// 
        /// <param name="Size">Leaf size</param>
        public void SetTreeLeafSize(byte Size)
        {
            m_configString[2] &= ~(ulong)0xff;
            m_configString[2] |= (ulong)Size;
        }

        /// <summary>
        /// Set the tree fan out size
        /// </summary>
        /// 
        /// <param name="Size">Fan out size</param>
        public void SetTreeFanOutSize(byte Size)
        {
            m_configString[2] &= ~((ulong)0xff << 8);
            m_configString[2] |= (ulong)Size << 8;
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
                throw new CryptoHashException("Skein256:SetMaxTreeHeight", "Tree height must be zero or greater than 1.", new Exception());

            m_configString[2] &= ~((ulong)0xff << 16);
            m_configString[2] |= (ulong)Height << 16;
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            // copy the configuration value to the state
            for (int i = 0; i < m_digestState.Length; i++)
                m_digestState[i] = m_configValue[i];

            // set up tweak for message block
            m_ubiParameters.StartNewBlockType(UbiType.Message);

            // reset bytes filled
            m_bytesFilled = 0;
        }

        private void ProcessBlock(int bytes)
        {
            // set the key to the current state
            m_blockCipher.SetKey(m_digestState);

            // update tweak
            m_ubiParameters.BitsProcessed += (long)bytes;
            m_blockCipher.SetTweak(m_ubiParameters.Tweak);

            // encrypt block
            m_blockCipher.Encrypt(m_cipherInput, m_digestState);

            // feed-forward input with state
            for (int i = 0; i < m_cipherInput.Length; i++)
                m_digestState[i] ^= m_cipherInput[i];
        }

        private static ulong BytesToUInt64(byte[] Input, int InOffset)
        {
            ulong n = Input[InOffset];
            n |= (ulong)Input[InOffset + 1] << 8;
            n |= (ulong)Input[InOffset + 2] << 16;
            n |= (ulong)Input[InOffset + 3] << 24;
            n |= (ulong)Input[InOffset + 4] << 32;
            n |= (ulong)Input[InOffset + 5] << 40;
            n |= (ulong)Input[InOffset + 6] << 48;
            n |= (ulong)Input[InOffset + 7] << 56;

            return n;
        }

        private static void PutBytes(ulong[] Input, byte[] Output, int Offset, int ByteCount)
        {
            int j = 0;
            for (int i = 0; i < ByteCount; i++)
            {
                Output[Offset + i] = (byte)((Input[i / 8] >> j) & 0xff);
                j = (j + 8) % 64;
            }
        }
        #endregion

        #region Threefish256
        private class Threefish256
        {
            #region Constants
            private const int CipherSize = 256;
            private const int CipherQwords = CipherSize / 64;
            private const int ExpandedKeySize = CipherQwords + 1;
            private const ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;
            private const int ExpandedTweakSize = 3;
            #endregion

            #region Fields
            private ulong[] _expandedKey;
            private ulong[] _expandedTweak;
            #endregion

            #region Constructor
            internal Threefish256()
            {
                // create the expanded key array
                _expandedTweak = new ulong[ExpandedTweakSize];
                _expandedKey = new ulong[ExpandedKeySize];
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

            internal void Encrypt(ulong[] input, ulong[] output)
            {
                // cache the block, key, and tweak
                ulong b0 = input[0];
                ulong b1 = input[1];
                ulong b2 = input[2];
                ulong b3 = input[3];
                ulong k0 = _expandedKey[0];
                ulong k1 = _expandedKey[1];
                ulong k2 = _expandedKey[2];
                ulong k3 = _expandedKey[3];
                ulong k4 = _expandedKey[4];
                ulong t0 = _expandedTweak[0];
                ulong t1 = _expandedTweak[1];
                ulong t2 = _expandedTweak[2];

                Mix(ref b0, ref b1, 14, k0, k1 + t0);
                Mix(ref b2, ref b3, 16, k2 + t1, k3);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k1, k2 + t1);
                Mix(ref b2, ref b3, 33, k3 + t2, k4 + 1);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k2, k3 + t2);
                Mix(ref b2, ref b3, 16, k4 + t0, k0 + 2);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k3, k4 + t0);
                Mix(ref b2, ref b3, 33, k0 + t1, k1 + 3);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k4, k0 + t1);
                Mix(ref b2, ref b3, 16, k1 + t2, k2 + 4);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k0, k1 + t2);
                Mix(ref b2, ref b3, 33, k2 + t0, k3 + 5);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k1, k2 + t0);
                Mix(ref b2, ref b3, 16, k3 + t1, k4 + 6);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k2, k3 + t1);
                Mix(ref b2, ref b3, 33, k4 + t2, k0 + 7);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k3, k4 + t2);
                Mix(ref b2, ref b3, 16, k0 + t0, k1 + 8);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k4, k0 + t0);
                Mix(ref b2, ref b3, 33, k1 + t1, k2 + 9);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k0, k1 + t1);
                Mix(ref b2, ref b3, 16, k2 + t2, k3 + 10);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k1, k2 + t2);
                Mix(ref b2, ref b3, 33, k3 + t0, k4 + 11);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k2, k3 + t0);
                Mix(ref b2, ref b3, 16, k4 + t1, k0 + 12);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k3, k4 + t1);
                Mix(ref b2, ref b3, 33, k0 + t2, k1 + 13);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k4, k0 + t2);
                Mix(ref b2, ref b3, 16, k1 + t0, k2 + 14);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k0, k1 + t0);
                Mix(ref b2, ref b3, 33, k2 + t1, k3 + 15);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k1, k2 + t1);
                Mix(ref b2, ref b3, 16, k3 + t2, k4 + 16);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k2, k3 + t2);
                Mix(ref b2, ref b3, 33, k4 + t0, k0 + 17);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);

                output[0] = b0 + k3;
                output[1] = b1 + k4 + t0;
                output[2] = b2 + k0 + t1;
                output[3] = b3 + k1 + 18;
            }
            #endregion

            #region Private Methods
            private static ulong RotateLeft64(ulong V, int B)
            {
                return (V << B) | (V >> (64 - B));
            }

            private static ulong RotateRight64(ulong V, int B)
            {
                return (V >> B) | (V << (64 - B));
            }

            private static void Mix(ref ulong A, ref ulong B, int R)
            {
                A += B;
                B = RotateLeft64(B, R) ^ A;
            }

            private static void Mix(ref ulong A, ref ulong B, int R, ulong K0, ulong K1)
            {
                B += K1;
                A += B + K0;
                B = RotateLeft64(B, R) ^ A;
            }

            private static void UnMix(ref ulong A, ref ulong B, int R)
            {
                B = RotateRight64(B ^ A, R);
                A -= B;
            }

            private static void UnMix(ref ulong A, ref ulong B, int R, ulong K0, ulong K1)
            {
                B = RotateRight64(B ^ A, R);
                A -= B + K0;
                B -= K1;
            }

            internal void SetTweak(ulong[] Tweak)
            {
                _expandedTweak[0] = Tweak[0];
                _expandedTweak[1] = Tweak[1];
                _expandedTweak[2] = Tweak[0] ^ Tweak[1];
            }

            internal void SetKey(ulong[] Key)
            {
                int i;
                ulong parity = KeyScheduleConst;

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
                    if (m_blockCipher != null)
                    {
                        m_blockCipher.Clear();
                        m_blockCipher = null;
                    }
                    if (m_cipherInput != null)
                    {
                        Array.Clear(m_cipherInput, 0, m_cipherInput.Length);
                        m_cipherInput = null;
                    }
                    if (m_digestState != null)
                    {
                        Array.Clear(m_digestState, 0, m_digestState.Length);
                        m_digestState = null;
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
