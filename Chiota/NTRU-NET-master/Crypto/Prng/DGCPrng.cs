using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.Exceptions;

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>DGCPrng: An implementation of a Digest Counter based Random Number Generator.</h3>
    /// <para>Uses a Digest Counter DRBG as outlined in NIST document: SP800-90A<cite>SP800-90A</cite></para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IRandom</c> interface:</description>
    /// <code>
    /// int num;
    /// using (IRandom rnd = new DGCPrng([Digests])
    ///     num = rnd.Next([Minimum], [Maximum]);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/09" version="1.4.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest">VTDev.Libraries.CEXEngine.Crypto.Digest Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any <see cref="Digests">digest</see>.</description></item>
    /// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
    /// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-90A: <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Appendix E1.</see></description></item>
    /// <item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
    /// <item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
    /// <item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
    /// <item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class DGCPrng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "DGCPrng";
        private const int BUFFER_SIZE = 1024;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private IDigest _digestEngine;
        private Digests _digestType;
        private ISeed _seedGenerator;
        private SeedGenerators _seedType;
        private DGCDrbg _rngGenerator;
        private byte[] _stateSeed;
        private byte[] _byteBuffer;
        private int _bufferIndex = 0;
        private int _bufferSize = 0;
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
        /// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
        /// <param name="SeedEngine">The Seed engine used to create the salt (default is CSPRsg)</param>
        /// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the buffer size is too small</exception>
        public DGCPrng(Digests DigestEngine = Digests.Keccak512, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, int BufferSize = BUFFER_SIZE)
        {
            if (BufferSize < 128)
                throw new CryptoRandomException("DGCPrng:Ctor", "BufferSize must be at least 128 bytes!", new ArgumentException());

            _digestType = DigestEngine;
            _seedType = SeedEngine;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            Reset();
        }

        /// <summary>
        /// Initialize the class with a Seed; note: the same seed will produce the same random output
        /// </summary>
        /// 
        /// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
        /// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
        /// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or buffer size is too small; (min. seed = digest blocksize + 8)</exception>
        public DGCPrng(byte[] Seed, Digests DigestEngine = Digests.Keccak512, int BufferSize = BUFFER_SIZE)
        {
            if (Seed == null)
                throw new CryptoRandomException("DGCPrng:Ctor", "Seed can not be null!", new ArgumentNullException());
            if (GetMinimumSeedSize(DigestEngine) < Seed.Length)
                throw new CryptoRandomException("DGCPrng:Ctor", String.Format("The state seed is too small! must be at least {0} bytes", GetMinimumSeedSize(DigestEngine)), new ArgumentException());
            if (BufferSize < 128)
                throw new CryptoRandomException("DGCPrng:Ctor", "BufferSize must be at least 128 bytes!", new ArgumentException());

            _digestType = DigestEngine;
            _stateSeed = Seed;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            Reset();
        }

        private DGCPrng()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DGCPrng()
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
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
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
            if (_digestEngine != null)
            {
                _digestEngine.Dispose();
                _digestEngine = null;
            }
            if (_seedGenerator != null)
            {
                _seedGenerator.Dispose();
                _seedGenerator = null;
            }

            _digestEngine = GetDigest(_digestType);
            _rngGenerator = new DGCDrbg(_digestEngine);

            if (_stateSeed != null)
            {
                _rngGenerator.Initialize(_stateSeed);
            }
            else
            {
                _seedGenerator = GetSeedGenerator(_seedType);
                _rngGenerator.Initialize(_seedGenerator.GetSeed((_digestEngine.BlockSize * 2) + 8));   // 2 * block + counter (2*bs+8)
            }

            _rngGenerator.Generate(_byteBuffer);
            _bufferIndex = 0;
        }
        #endregion

        #region Private Methods
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

        private IDigest GetDigest(Digests RngEngine)
        {
            switch (RngEngine)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak1024:
                    return new Keccak1024();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein1024:
                    return new Skein1024();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                default:
                    return new SHA512();
            }
        }

        private int GetMinimumSeedSize(Digests RngEngine)
        {
            int ctrLen = 8;

            switch (RngEngine)
            {
                case Digests.Blake256:
                    return ctrLen + 32;
                case Digests.Blake512:
                    return ctrLen + 64;
                case Digests.Keccak1024:
                    return ctrLen + 72;
                case Digests.Keccak256:
                    return ctrLen + 136;
                case Digests.Keccak512:
                    return ctrLen + 72;
                case Digests.SHA256:
                    return ctrLen + 64;
                case Digests.SHA512:
                    return ctrLen + 128;
                case Digests.Skein1024:
                    return ctrLen + 128;
                case Digests.Skein256:
                    return ctrLen + 32;
                case Digests.Skein512:
                    return ctrLen + 64;
                default:
                    return ctrLen + 128;
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
