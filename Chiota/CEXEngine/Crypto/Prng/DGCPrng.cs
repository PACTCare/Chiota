using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// DGCPrng: An implementation of a Digest Counter based Random Number Generator
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">digest</see>.</description></item>
    /// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
    /// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">SP800-90A</a>: Appendix E1.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the NIST Codebook-based: Deterministic Random Bit Generator.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class DGCPrng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "DGCPrng";
        private const int BUFFER_SIZE = 1024;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private IDigest m_digestEngine;
        private Digests m_digestType;
        private ISeed m_seedGenerator;
        private SeedGenerators m_seedType;
        private DGC m_rngGenerator;
        private byte[] m_stateSeed;
        private byte[] m_byteBuffer;
        private int m_bufferIndex = 0;
        private int m_bufferSize = 0;
        private object m_objLock = new object();
        #endregion

        #region Properties
        /// <summary>
        /// Get: The prngs type name
        /// </summary>
        public Prngs Enumeral
        {
            get { return Prngs.DGCPrng; }
        }

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

            m_digestType = DigestEngine;
            m_seedType = SeedEngine;
            m_byteBuffer = new byte[BufferSize];
            m_bufferSize = BufferSize;
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

            m_digestType = DigestEngine;
            m_stateSeed = Seed;
            m_byteBuffer = new byte[BufferSize];
            m_bufferSize = BufferSize;
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
        /// <param name="Output">Array to fill with random bytes</param>
        public void GetBytes(byte[] Output)
        {
            lock (m_objLock)
            {
                if (m_byteBuffer.Length - m_bufferIndex < Output.Length)
                {
                    int bufSize = m_byteBuffer.Length - m_bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, Output, 0, bufSize);
                    int rem = Output.Length - bufSize;

                    while (rem > 0)
                    {
                        // fill buffer
                        m_rngGenerator.Generate(m_byteBuffer);

                        if (rem > m_byteBuffer.Length)
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, Output, bufSize, m_byteBuffer.Length);
                            bufSize += m_byteBuffer.Length;
                            rem -= m_byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, Output, bufSize, rem);
                            m_bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, Output, 0, Output.Length);
                    m_bufferIndex += Output.Length;
                }
            }
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
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
        /// <returns>Random int</returns>
        public int Next(int Maximum)
        {
            byte[] rand;
            int[] num = new int[1];

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
        /// <returns>Random int</returns>
        public int Next(int Minimum, int Maximum)
        {
            int num = 0;
            while ((num = Next(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
        public long NextLong()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }
        
        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        public long NextLong(long Maximum)
        {
            byte[] rand;
            long[] num = new long[1];

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
        /// <returns>Random long</returns>
        public long NextLong(long Minimum, long Maximum)
        {
            long num = 0;
            while ((num = NextLong(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Reset the DGCPrng instance
        /// </summary>
        public void Reset()
        {
            if (m_digestEngine != null)
            {
                m_digestEngine.Dispose();
                m_digestEngine = null;
            }
            if (m_seedGenerator != null)
            {
                m_seedGenerator.Dispose();
                m_seedGenerator = null;
            }

            m_digestEngine = GetDigest(m_digestType);
            m_rngGenerator = new DGC(m_digestEngine);

            if (m_stateSeed != null)
            {
                m_rngGenerator.Initialize(m_stateSeed);
            }
            else
            {
                m_seedGenerator = GetSeedGenerator(m_seedType);
                m_rngGenerator.Initialize(m_seedGenerator.GetBytes((m_digestEngine.BlockSize * 2) + 8));   // 2 * block + counter (2*bsz+8)
            }

            m_rngGenerator.Generate(m_byteBuffer);
            m_bufferIndex = 0;
        }
        #endregion

        #region Private Methods
        private byte[] GetByteRange(long Maximum)
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

        private byte[] GetBits(byte[] Data, long Maximum)
        {
            ulong[] val = new ulong[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > (ulong)Maximum && bits > 0)
            {
                val[0] >>= 1;
                bits--;
            }

            byte[] ret = new byte[Data.Length];
            Buffer.BlockCopy(val, 0, ret, 0, Data.Length);

            return ret;
        }

        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoRandomException("DGCPrng:GetDigest", "The digest type is not recognized!", new ArgumentException());
            }
        }

        private int GetMinimumSeedSize(Digests DigestType)
        {
            int ctrLen = 8;

            switch (DigestType)
            {
                case Digests.Blake2S256:
                    return ctrLen + 32;
                case Digests.Blake2B512:
                    return ctrLen + 64;
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

        private ISeed GetSeedGenerator(SeedGenerators SeedType)
        {
            try
            {
                return SeedGeneratorFromName.GetInstance(SeedType);
            }
            catch
            {
                throw new CryptoRandomException("DGCPrng:GetSeedGenerator", "The seed generator is not recognized!", new ArgumentException());
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
                    if (m_rngGenerator != null)
                    {
                        m_rngGenerator.Dispose();
                        m_rngGenerator = null;
                    }
                    if (m_seedGenerator != null)
                    {
                        m_seedGenerator.Dispose();
                        m_seedGenerator = null;
                    }
                    if (m_byteBuffer != null)
                    {
                        Array.Clear(m_byteBuffer, 0, m_byteBuffer.Length);
                        m_byteBuffer = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
