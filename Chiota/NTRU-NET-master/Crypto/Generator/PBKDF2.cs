#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// <h3>PBKDF2: An implementation of an Hash based Key Derivation Function.</h3>
    /// <para>PBKDF2 as outlined in ISO 18033-2 <cite>ISO 18033</cite>.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new PBKDF2(new SHA512()))
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
    ///     <revision date="2015/28/15" version="1.3.1.1">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mac.HMAC">VTDev.Libraries.CEXEngine.Crypto.Mac.HMAC HMAC</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest">VTDev.Libraries.CEXEngine.Crypto.Digest Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto">VTDev.Libraries.CEXEngine.Crypto Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with a <see cref="Digests">Digest</see> or a Mac.</description></item>
    /// <item><description>The <see cref="HKDF(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Salt size should be multiple of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="bullet">
    /// <item><description>ISO-18033-2: <see href="http://www.shoup.net/iso/std6.pdf">Specification</see>.</description></item>
    /// <item><description>RFC 2898: <see href="http://tools.ietf.org/html/rfc2898">Specification</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public class PBKDF2 : IGenerator, IDisposable
    {
        #region Constants
        private const string ALG_NAME = "PBKDF2";
        #endregion

        #region Fields
        private IDigest _digest;
        private byte[] _Salt;
        private byte[] _IV;
        private bool _disposeEngine = true;
        private int _hashLength;
        private bool _isInitialized = false;
        private int _keySize = 64;
        private bool _isDisposed = false;
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
        /// Creates a PBKDF2 Bytes Generator based on the given HMAC function
        /// </summary>
        public PBKDF2()
        {
            _disposeEngine = true;
            _digest = new SHA512();
            _hashLength = _digest.DigestSize;
            _keySize = _digest.BlockSize;
        }

        /// <summary>
        /// Creates a PBKDF2 Bytes Generator based on the given hash function
        /// </summary>
        /// 
        /// <param name="Digest">The digest used</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Digest is used</exception>
        public PBKDF2(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new ArgumentNullException("Digest can not be null!");

            _disposeEngine = DisposeEngine;
            _digest = Digest;
            _hashLength = Digest.DigestSize;
            _keySize = Digest.BlockSize;
        }
        
        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PBKDF2()
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
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt is used</exception>
        public void Initialize(byte[] Salt)
        {
            if (Salt == null)
                throw new ArgumentNullException("Salt can not be null!");
            //if (Salt.Length < _digest.BlockSize)
            //    throw new ArgumentException("Salt can not be less than digest blocksize!");

            if (Salt.Length < _digest.BlockSize * 2)
            {
                _Salt = new byte[Salt.Length];
                // interpret as ISO18033, no IV
                Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length);
            }
            else
            {
                byte[] keyBytes = new byte[_digest.DigestSize];
                _Salt = new byte[Salt.Length - _digest.DigestSize];
                Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length - _digest.DigestSize);
                Buffer.BlockCopy(Salt, _Salt.Length, keyBytes, 0, _digest.DigestSize);

                _IV = keyBytes;
            }
            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt or Ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm)
        {
            if (Salt == null)
                throw new ArgumentNullException("Salt can not be null!");
            if (Ikm == null)
                throw new ArgumentNullException("Ikm can not be null!");
            if (Salt.Length < _digest.BlockSize)
                throw new ArgumentException("Salt can not be less than digest blocksize!");

            _Salt = (byte[])Salt.Clone();
            _IV = (byte[])Ikm.Clone();
            
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
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt or Ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm, byte[] Nonce)
        {
            if (Salt == null)
                throw new ArgumentNullException("Salt can not be null!");
            if (Ikm == null)
                throw new ArgumentNullException("Ikm can not be null!");
            if (Salt.Length < _digest.BlockSize)
                throw new ArgumentException("Salt can not be less than digest blocksize!");

            _IV = (byte[])Ikm.Clone();
            _Salt = new byte[Salt.Length + Nonce.Length];
            Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length);
            Buffer.BlockCopy(Nonce, 0, _Salt, Salt.Length, Nonce.Length);

            _isInitialized = true;
        }

        /// <summary>
        /// Generate a block of cryptographically secure pseudo random bytes
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
        /// Generate cryptographically secure pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        public int Generate(byte[] Output, int OutOffset, int Size)
        {
            if ((Output.Length - Size) < OutOffset)
				throw new Exception("Output buffer too small");

            return GenerateKey(Output, OutOffset, Size);
        }

        /// <summary>
        /// Update the Seed material
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            Initialize(Seed);
        }
        #endregion

        #region Helpers
        private int GenerateKey(byte[] Output, int OutOffset, int Size)
		{
			int outLen = _digest.DigestSize;
            int maxCtr = (int)((Size + outLen - 1) / outLen);
            // only diff between v 1 & 2
			int counter = 1;
			byte[] hash = new byte[_digest.DigestSize];

			for (int i = 0; i < maxCtr; i++)
			{
                _digest.BlockUpdate(_Salt, 0, _Salt.Length);
				_digest.Update((byte)(counter >> 24));
				_digest.Update((byte)(counter >> 16));
				_digest.Update((byte)(counter >> 8));
				_digest.Update((byte)counter);

				if (_IV != null)
                    _digest.BlockUpdate(_IV, 0, _IV.Length);

				_digest.DoFinal(hash, 0);

				if (Size > outLen)
				{
					Array.Copy(hash, 0, Output, OutOffset, outLen);
					OutOffset += outLen;
					Size -= outLen;
				}
				else
				{
					Array.Copy(hash, 0, Output, OutOffset, Size);
				}

				counter++;
			}

			_digest.Reset();

            return Size;
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
                    if (_digest != null && _disposeEngine)
                    {
                        _digest.Dispose();
                        _digest = null;
                    }
                    if (_IV != null)
                    {
                        Array.Clear(_IV, 0, _IV.Length);
                        _IV = null;
                    }
                    if (_Salt != null)
                    {
                        Array.Clear(_Salt, 0, _Salt.Length);
                        _Salt = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
