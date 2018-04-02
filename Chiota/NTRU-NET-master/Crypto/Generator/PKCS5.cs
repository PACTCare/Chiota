#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// <h3>PKCS5 V2: An implementation of an Hash based Key Derivation Function.</h3>
    /// <para>PKCS5 Version 2, as outlined in RFC 2898<cite>RFC 2898</cite></para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new PKCS5(new SHA512(), 10000))
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, Ikm, [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/28/15" version="1.3.1.1">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mac.HMAC">VTDev.Libraries.CEXEngine.Crypto.Mac HMAC</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with a <see cref="Digests">Digest</see> or a <see cref="Macs">Mac</see>.</description></item>
    /// <item><description>The <see cref="PKCS5(IDigest, int, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Salt size should be multiple of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>RFC 2898: <see href="http://tools.ietf.org/html/rfc2898">Specification</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public class PKCS5 : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "PKCS5";
        #endregion

        #region Fields
        private IMac _digestMac;
        private byte[] _Salt;
        private int _Iterations = 1;
        private bool _disposeEngine = true;
        private int _hashLength;
        private bool _isInitialized = false;
        private int _keySize = 64;
        private bool _isDisposed = false;
        private KeyParams _macKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator is ready to produce data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// <para>Minimum initialization key size in bytes; 
        /// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
        /// </summary>
        public int KeySize
        {
            get { return _keySize; }
            private set { _keySize = value; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Creates a PKCS5 Bytes Generator using the default SHA512 HMAC engine
        /// </summary>
        /// 
        /// <param name="Iterations">The number of cycles used to produce output</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid Iterations count is used</exception>
        public PKCS5(int Iterations)
        {
            if (Iterations < 1)
                throw new CryptoGeneratorException("PKCS5:Ctor", "Iterations count can not be less than 1!", new ArgumentException());

            _Iterations = Iterations;
            _disposeEngine = true;
            _digestMac = new SHA512HMAC();
            _hashLength = _digestMac.DigestSize;
            _keySize = _digestMac.BlockSize;
        }

        /// <summary>
        /// Creates a PKCS5 Bytes Generator based on the given hash function
        /// </summary>
        /// 
        /// <param name="Digest">The digest used</param>
        /// <param name="Iterations">The number of cycles used to produce output</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Digest or Iterations count is used</exception>
        public PKCS5(IDigest Digest, int Iterations, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("PKCS5:Ctor", "Digest can not be null!", new ArgumentNullException());
            if (Iterations < 1)
                throw new CryptoGeneratorException("PKCS5:Ctor", "Iterations count can not be less than 1!", new ArgumentException());

            _Iterations = Iterations;
            _disposeEngine = DisposeEngine;
            _digestMac = new HMAC(Digest);
            _hashLength = Digest.DigestSize;
            _keySize = Digest.BlockSize;
        }

        /// <summary>
        /// Creates a PKCS5 Bytes Generator based on the given HMAC function
        /// </summary>
        /// 
        /// <param name="Hmac">The HMAC digest used</param>
        /// <param name="Iterations">The number of cycles used to produce output</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Hmac or invalid Iterations count is used</exception>
        public PKCS5(IMac Hmac, int Iterations, bool DisposeEngine = true)
        {
            if (Hmac == null)
                throw new CryptoGeneratorException("PKCS5:Ctor", "Hmac can not be null!", new ArgumentNullException());
            if (Iterations < 1)
                throw new CryptoGeneratorException("PKCS5:Ctor", "Iterations count can not be less than 1!", new ArgumentException());

            _Iterations = Iterations;
            _disposeEngine = DisposeEngine;
            _digestMac = Hmac;
            _hashLength = Hmac.DigestSize;
            _keySize = Hmac.BlockSize;
        }

        private PKCS5()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PKCS5()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt is used</exception>
        public void Initialize(byte[] Salt)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("PKCS5:Initialize", "Salt can not be null!", new ArgumentNullException());

            byte[] keyBytes = new byte[_digestMac.DigestSize];
            Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length - _digestMac.DigestSize);
            Buffer.BlockCopy(Salt, _Salt.Length, keyBytes, 0, _digestMac.DigestSize);

            _macKey = new KeyParams(keyBytes);

            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt or Ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("PKCS5:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Ikm == null)
                throw new CryptoGeneratorException("PKCS5:Initialize", "IKM can not be null!", new ArgumentNullException());

            _Salt = (byte[])Salt.Clone();
            _macKey = new KeyParams(Ikm);

            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Nonce">Nonce value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt or Ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm, byte[] Nonce)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("PKCS5:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Ikm == null)
                throw new CryptoGeneratorException("PKCS5:Initialize", "IKM can not be null!", new ArgumentNullException());

            _macKey = new KeyParams(Ikm);
            _Salt = new byte[Salt.Length + Nonce.Length];

            Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length);
            Buffer.BlockCopy(Nonce, 0, _Salt, Salt.Length, Nonce.Length);

            _isInitialized = true;
        }

        /// <summary>
        /// Generate a block of pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        public int Generate(byte[] Output)
        {
            return GenerateKey(Output, 0, Output.Length);
        }

        /// <summary>
        /// Generate pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if the output buffer is too small</exception>
        public int Generate(byte[] Output, int OutOffset, int Size)
        {
            if ((Output.Length - Size) < OutOffset)
                throw new CryptoGeneratorException("PKCS5:Generate", "Output buffer too small!", new Exception());

            return GenerateKey(Output, OutOffset, Size);
        }

        /// <summary>
        /// Update the Seed material
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("PKCS5:Update", "Seed can not be null!", new ArgumentNullException());

            Initialize(Seed);
        }
        #endregion

        #region Private Methods
        private int GenerateKey(byte[] Output, int OutOffset, int Size)
        {
            int hashLen = _digestMac.DigestSize;
            int diff = Size % hashLen;
            int max = Size / hashLen;
            int ctr = 0;
            byte[] buffer = new byte[4];
            byte[] outBytes = new byte[Size];

            for (ctr = 0; ctr < max; ctr++)
            {
                IntToOctet(buffer, ctr + 1);
                Process(buffer, outBytes, ctr * hashLen);
            }

            if (diff > 0)
            {
                IntToOctet(buffer, ctr + 1);
                byte[] rem = new byte[hashLen];
                Process(buffer, rem, 0);
                Buffer.BlockCopy(rem, 0, outBytes, outBytes.Length - diff, diff);
            }

            Buffer.BlockCopy(outBytes, 0, Output, OutOffset, outBytes.Length);
            return Size;
        }

        private void IntToOctet(byte[] Output, int Counter)
        {
            Output[0] = (byte)((uint)Counter >> 24);
            Output[1] = (byte)((uint)Counter >> 16);
            Output[2] = (byte)((uint)Counter >> 8);
            Output[3] = (byte)Counter;
        }

        private void Process(byte[] Input, byte[] Output, int OutOffset)
        {
            byte[] state = new byte[_digestMac.DigestSize];

            _digestMac.Initialize(_macKey);

            if (_Salt != null)
                _digestMac.BlockUpdate(_Salt, 0, _Salt.Length);

            _digestMac.BlockUpdate(Input, 0, Input.Length);
            _digestMac.DoFinal(state, 0);

            Array.Copy(state, 0, Output, OutOffset, state.Length);

            for (int count = 1; count != _Iterations; count++)
            {
                _digestMac.Initialize(_macKey);
                _digestMac.BlockUpdate(state, 0, state.Length);
                _digestMac.DoFinal(state, 0);

                for (int j = 0; j != state.Length; j++)
                    Output[OutOffset + j] ^= state[j];
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (_digestMac != null && _disposeEngine)
                    {
                        _digestMac.Dispose();
                        _digestMac = null;
                    }
                    if (_macKey != null)
                    {
                        _macKey.Dispose();
                        _macKey = null;
                    }
                    if (_Salt != null)
                    {
                        Array.Clear(_Salt, 0, _Salt.Length);
                        _Salt = null;
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

