#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>CTRPrng: An implementation of a Encryption Counter based Deterministic Random Number Generator.</h3>
    /// <para>A Block Cipher Counter DRBG as outlined in NIST document: SP800-90A<cite>SP800-90B</cite></para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IRandom</c> interface:</description>
    /// <code>
    /// int num;
    /// using (IRandom rnd = new CTRPrng([BlockCiphers], [SeedGenerators]))
    /// {
    ///     // get random int
    ///     num = rnd.Next([Minimum], [Maximum]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/09" version="1.4.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Seed">VTDev.Libraries.CEXEngine.Crypto.Seed ISeed Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any block <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">cipher</see>.</description></item>
    /// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
    /// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
    /// <item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
    /// <item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
    /// <item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CTRPrng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "CTRPrng";
        private const int BUFFER_SIZE = 4096;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private IBlockCipher _rngEngine;
        private CTRDrbg _rngGenerator;
        private ISeed _seedGenerator;
        private BlockCiphers _engineType;
        private SeedGenerators _seedType;
        private byte[] _stateSeed;
        private byte[] _byteBuffer;
        private int _bufferIndex = 0;
        private int _bufferSize = 0;
        private int _keySize = 0;
        private object _objLock = new object();
        #endregion

        #region Properties
        /// <summary>
        /// Algorithm name
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
        /// <param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
        /// <param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// <param name="KeySize">The key size (in bytes) of the symmetric cipher; a <c>0</c> value will auto size the key</param>
        public CTRPrng(BlockCiphers BlockEngine = BlockCiphers.RDX, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, int BufferSize = 4096, int KeySize = 0)
        {
            if (BufferSize < 64)
                throw new CryptoRandomException("CTRPrng:Ctor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());

            _engineType = BlockEngine;
            _seedType = SeedEngine;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            if (KeySize > 0)
                _keySize = KeySize;
            else
                _keySize = GetKeySize(BlockEngine);

            Reset();
        }

        /// <summary>
        /// Initialize the class with a Seed; note: the same seed will produce the same random output
        /// </summary>
        /// 
        /// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + counter 16)</param>
        /// <param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or too small</exception>
        public CTRPrng(byte[] Seed, BlockCiphers BlockEngine = BlockCiphers.RDX, int BufferSize = 4096)
        {
            if (BufferSize < 64)
                throw new CryptoRandomException("CTRPrng:Ctor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());
            if (Seed == null)
                throw new CryptoRandomException("CTRPrng:Ctor", "Seed can not be null!", new ArgumentNullException());
            if (GetKeySize(BlockEngine) < Seed.Length)
                throw new CryptoRandomException("CTRPrng:Ctor", String.Format("The state seed is too small! must be at least {0} bytes", GetKeySize(BlockEngine)), new ArgumentException());

            _engineType = BlockEngine;
            _stateSeed = Seed;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CTRPrng()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];

            GetBytes(data);

            return data;
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            lock (_objLock)
            {
                if (_byteBuffer.Length - _bufferIndex < Data.Length)
                {
                    int bufSize = _byteBuffer.Length - _bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, Data, 0, bufSize);
                    int rem = Data.Length - bufSize;

                    while (rem > 0)
                    {
                        // fill buffer
                        _rngGenerator.Generate(_byteBuffer);

                        if (rem > _byteBuffer.Length)
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, Data, bufSize, _byteBuffer.Length);
                            bufSize += _byteBuffer.Length;
                            rem -= _byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, Data, bufSize, rem);
                            _bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, Data, 0, Data.Length);
                    _bufferIndex += Data.Length;
                }
            }
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public int Next()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next(int Maximum)
        {
            byte[] rand;
            Int32[] num = new Int32[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next(int Minimum, int Maximum)
        {
            Int32 num = 0;
            while ((num = Next(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Get a pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong(long Maximum)
        {
            byte[] rand;
            Int64[] num = new Int64[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong(long Minimum, long Maximum)
        {
            Int64 num = 0;
            while ((num = NextLong(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Reset the RNGCryptoServiceProvider instance.
        /// </summary>
        public void Reset()
        {
            if (_rngEngine != null)
            {
                _rngEngine.Dispose();
                _rngEngine = null;
            }
            if (_seedGenerator != null)
            {
                _seedGenerator.Dispose();
                _seedGenerator = null;
            }
            if (_rngGenerator != null)
            {
                _rngGenerator.Dispose();
                _rngGenerator = null;
            }

            _rngEngine = GetCipher(_engineType);
            _seedGenerator = GetSeedGenerator(_seedType);
            _rngGenerator = new CTRDrbg(_rngEngine, true, _keySize);

            if (_seedGenerator != null)
                _rngGenerator.Initialize(_seedGenerator.GetSeed(_rngEngine.BlockSize + _keySize));
            else
                _rngGenerator.Initialize(_stateSeed);

            _rngGenerator.Generate(_byteBuffer);
            _bufferIndex = 0;
        }
        #endregion

        #region Private Methods
        private byte[] GetBits(byte[] Data, Int64 Maximum)
        {
            UInt64[] val = new UInt64[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > (UInt64)Maximum && bits > 0)
            {
                val[0] >>= 1;
                bits--;
            }

            byte[] ret = new byte[Data.Length];
            Buffer.BlockCopy(val, 0, ret, 0, Data.Length);

            return ret;
        }

        private byte[] GetByteRange(Int64 Maximum)
        {
            byte[] data;

            if (Maximum < 256)
                data = GetBytes(1);
            else if (Maximum < 65536)
                data = GetBytes(2);
            else if (Maximum < 16777216)
                data = GetBytes(3);
            else if (Maximum < 4294967296)
                data = GetBytes(4);
            else if (Maximum < 1099511627776)
                data = GetBytes(5);
            else if (Maximum < 281474976710656)
                data = GetBytes(6);
            else if (Maximum < 72057594037927936)
                data = GetBytes(7);
            else
                data = GetBytes(8);

            return GetBits(data, Maximum);
        }

        private IBlockCipher GetCipher(BlockCiphers RngEngine)
        {
            switch (RngEngine)
            {
                case BlockCiphers.RDX:
                    return new RDX();
                case BlockCiphers.RHX:
                    return new RHX();
                case BlockCiphers.RSM:
                    return new RSM();
                case BlockCiphers.SHX:
                    return new SHX();
                case BlockCiphers.SPX:
                    return new SPX();
                case BlockCiphers.TFX:
                    return new TFX();
                case BlockCiphers.THX:
                    return new THX();
                case BlockCiphers.TSM:
                    return new TSM();
                default:
                    return new RDX();
            }
        }

        private int GetKeySize(BlockCiphers CipherEngine)
        {
            switch (CipherEngine)
            {
                case BlockCiphers.RHX:
                case BlockCiphers.RSM:
                case BlockCiphers.SHX:
                case BlockCiphers.THX:
                case BlockCiphers.TSM:
                    return 320;
                default:
                    return 32;
            }
        }

        private ISeed GetSeedGenerator(SeedGenerators SeedEngine)
        {
            switch (SeedEngine)
            {
                case SeedGenerators.XSPRsg:
                    return new XSPRsg();
                default:
                    return new CSPRsg();
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
                    if (_rngGenerator != null)
                    {
                        _rngGenerator.Dispose();
                        _rngGenerator = null;
                    }
                    if (_seedGenerator != null)
                    {
                        _seedGenerator.Dispose();
                        _seedGenerator = null;
                    }
                    if (_byteBuffer != null)
                    {
                        Array.Clear(_byteBuffer, 0, _byteBuffer.Length);
                        _byteBuffer = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
