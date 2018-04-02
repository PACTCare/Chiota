#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>SP20Prng: An implementation of a Encryption Counter based Deterministic Random Number Generator.</h3>
    /// <para>Uses the Salsa20 Key stream as a source of random input.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IRandom</c> interface:</description>
    /// <code>
    /// int num;
    /// using (IRandom rnd = new SP20Prng([SeedGenerators], [BufferSize], [SeedSize], [RoundsCount]))
    /// {
    ///     // get random int
    ///     num = rnd.Next([Minimum], [Maximum]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/14" version="1.4.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.</description></item>
    /// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/design.pdf">Design</see>.</description></item>
    /// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/security.pdf">Security</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class SP20Prng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "SP20Prng";
        private const int BUFFER_SIZE = 4096;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private SP20Drbg _rngGenerator;
        private ISeed _seedGenerator;
        private SeedGenerators _seedType;
        private byte[] _stateSeed;
        private byte[] _byteBuffer;
        private int _bufferIndex = 0;
        private int _bufferSize = 0;
        private int _keySize = 0;
        private int _dfnRounds = 20;
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
        /// <param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// <param name="SeedSize">The size of the seed to generate in bytes; can be 32 for a 128 bit key or 48 for a 256 bit key</param>
        /// <param name="Rounds">The number of diffusion rounds to use when generating the key stream</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or invalid, or rounds count is out of range</exception>
        public SP20Prng(SeedGenerators SeedEngine = SeedGenerators.CSPRsg, int BufferSize = 4096, int SeedSize = 48, int Rounds = 20)
        {
            if (BufferSize < 64)
                throw new CryptoRandomException("SP20Prng:CTor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());
            if (SeedSize != 32 && SeedSize != 48)
                throw new CryptoRandomException("SP20Prng:CTor", "Seed size must be 32 or 48 bytes (key + iv)!", new ArgumentException());
            if (Rounds < 10 || Rounds > 30 || Rounds % 2 > 0)
                throw new CryptoRandomException("SP20Prng:CTor", "Rounds must be an even number between 10 and 30!", new ArgumentOutOfRangeException());

            _dfnRounds = Rounds;
            _seedType = SeedEngine;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            _keySize = SeedSize;

            Reset();
        }

        /// <summary>
        /// Initialize the class with a Seed; note: the same seed will produce the same random output
        /// </summary>
        /// 
        /// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + iv of 16 bytes)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// <param name="Rounds">The number of diffusion rounds to use when generating the key stream</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or invalid, or rounds count is out of range</exception>
        public SP20Prng(byte[] Seed, int BufferSize = 4096, int Rounds = 20)
        {
            if (Seed == null)
                throw new CryptoRandomException("SP20Prng:CTor", "The Seed can not be null!", new ArgumentNullException());
            if (BufferSize < 64)
                throw new CryptoRandomException("SP20Prng:CTor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());
            if (Seed.Length != 32 && Seed.Length != 48)
                throw new CryptoRandomException("SP20Prng:CTor", "Seed size must be 32 or 48 bytes (key + iv)!", new ArgumentException());
            if (Rounds < 10 || Rounds > 30 || Rounds % 2 > 0)
                throw new CryptoRandomException("SP20Prng:CTor", "Rounds must be an even number between 10 and 30!", new ArgumentOutOfRangeException());

            _keySize = Seed.Length;
            _dfnRounds = Rounds;
            _stateSeed = Seed;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;

            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SP20Prng()
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

            _seedGenerator = GetSeedGenerator(_seedType);
            _rngGenerator = new SP20Drbg(_dfnRounds);

            if (_seedGenerator != null)
                _rngGenerator.Initialize(_seedGenerator.GetSeed(_keySize));
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

        private int GetKeySize()
        {
            return 48;
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
                    if (_stateSeed != null)
                    {
                        Array.Clear(_stateSeed, 0, _stateSeed.Length);
                        _stateSeed = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
