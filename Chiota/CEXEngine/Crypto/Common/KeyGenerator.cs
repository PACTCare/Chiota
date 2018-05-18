#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// KeyGenerator: A helper class for generating cryptographically strong keying material.
    /// <para>Generates an array or a populated KeyParams class, using a definable Digest(Drbg) dual stage generator.
    /// The first stage of the generator gets seed material from the selected seed generator, the second hashes the seed and adds the result to the state array.
    /// An optional (random) 32bit aligned counter array that can be prepended to the seed, sized either as 16 or 32 bytes. 
    /// The counter is incremented and prepended to the seed value before each hash call. 
    /// If the Counter parameter is set to null or <c>0</c> length in the constructor, or the default constructor is used, a 16 byte counter is generated 
    /// using the system default cryptographic service provider (CSPRsg).</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create an array of pseudo random keying material:</description>
    /// <code>
    /// byte[] rand;
    /// using (KeyGenerator gen = new KeyGenerator([SeedGenerator], [Digest], [Counter Size]))
    ///     // generate pseudo random bytes
    ///     rand = gen.Generate(Size);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng "/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom "/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>SHA-2 Generates key material using a two stage Hmac_k(Prng()) process.</description></item>
    /// <item><description>Blake, Keccak, and Skein also use a two stage generation method; Hash(Prng()).</description></item>
    /// <item><description>Seed Generator can be any of the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators"/>.</description></item>
    /// <item><description>Hash can be any of the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/> digests.</description></item>
    /// <item><description>Default Seed Generator is CSPRsg: <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RngCrypto</a>, default digest is SHA512.</description></item>
    /// <item><description>The counter is split into either 32 or 64bit integers, each rotated independently; the counters segment size can be set with the RotationalAlignment property.</description></item>
    /// <item><description>Resources are disposed of automatically.</description></item>
    /// </list>
    /// </remarks>
    public sealed class KeyGenerator : IDisposable
    {
        #region Constants
        private const int CTRDEF_SIZE = 16;
        private const int CTRMAX_SIZE = 32;
        private const int CTRMIN_SIZE = 16;
        #endregion

        #region Enums
        /// <summary>
        /// Counter rotational axis bit boundary 
        /// </summary>
        public enum CounterAlignmentSizes : int
        {
            /// <summary>
            /// Divide and rotate counter as 32bit integers
            /// </summary>
            RAP32,
            /// <summary>
            /// Divide and rotate counter as 64bit integers
            /// </summary>
            RAP64
        }
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private IDigest m_hashEngine;
        private ISeed m_seedEngine;
        private Digests m_dgtType;
        private SeedGenerators m_seedType;
        private byte[] m_ctrVector = null;
        private int m_ctrLength = 0;
        private CounterAlignmentSizes m_rotationalAlignment = CounterAlignmentSizes.RAP32;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the Digests enumeration member
        /// </summary>
        public Digests HashEngine 
        {
            get { return m_dgtType; }
            private set { m_dgtType = value; } 
        }

        /// <summary>
        /// Get/Set: Set the segmented counters integer sub-size.
        /// <para>The counter mechanism can rotate as a series of 32bit or 64bit integers. 
        /// For example; using a 16 byte counter length, when set to RAP64, the 16 bytes will be treated as 2 independent 64bit integers,
        /// each incremented independently by the counters rotational mechanism. If the RAP32 flag is set, the array would be treated as 
        /// 4 seperate 32bit integers.</para>
        /// </summary>
        public CounterAlignmentSizes RotationalAlignment
        {
            get { return m_rotationalAlignment; }
            set { m_rotationalAlignment = value; }
        }

        /// <summary>
        /// Get: Returns the Prng enumeration member
        /// </summary>
        public SeedGenerators SeedEngine 
        {
            get { return m_seedType; }
            private set { m_seedType = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class.
        /// <para>Initializes the class with default generators; SHA-2 512, and RNGCryptoServiceProvider.
        /// The digest counter mechanism is set to <c>O</c> (disabled) by default.</para>
        /// </summary>
        /// 
        /// <param name="SeedEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">generator</see> that supplies the seed material to the hash function</param>
        /// <param name="DigestEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> type used to post-process the pseudo random seed material</param>
        public KeyGenerator(SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests DigestEngine = Digests.SHA512)
        {
            // default engines
            m_seedType = SeedEngine;
            m_dgtType = DigestEngine;
            m_ctrLength = 0;

            // initialize the generators
            Reset();
        }

        /// <summary>
        /// Initialize the class and generators with a pseudo random counter vector.
        /// <para>The counter vector is a pseudo random, user supplied counter byte array; setting to a <c>0</c> value, produces a counter generated by the default random provider. 
        /// Valid values are <c>0</c> for auto-generation, or a 32bit aligned range between 16 and 32 bytes, i.e. 16, 20, 24, 28, and 32.</para>
        /// </summary>
        /// 
        /// <param name="SeedEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">generator</see> that supplies the seed material to the hash function</param>
        /// <param name="DigestEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> type used to post-process the pseudo random seed material</param>
        /// <param name="Counter">The random counter vector</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if the counter is not <c>0</c>, or a value between <c>4</c> and <c>32</c></exception>
        public KeyGenerator(SeedGenerators SeedEngine, Digests DigestEngine, byte[] Counter)
        {
            if (Counter == null)
                Counter = new byte[CTRDEF_SIZE];

            if (Counter.Length % 4 != 0 || Counter.Length > CTRMAX_SIZE || (Counter.Length < CTRMIN_SIZE && Counter.Length != 0))
                throw new CryptoGeneratorException("KeyGenerator:Ctor", "The counter size must be either 0, or between 16 and 32", new ArgumentException());

            m_seedType = SeedEngine;
            m_dgtType = DigestEngine;
            m_ctrVector = Counter;
            m_ctrLength = Counter.Length;

            // initialize the generators
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~KeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a populated KeyParams class
        /// </summary>
        /// 
        /// <param name="KeySize">Size of Key to generate in bytes</param>
        /// <param name="IVSize">Size of IV to generate in bytes</param>
        /// <param name="IKMSize">Size of IKM to generate in bytes</param>
        /// <param name="ExtKey">Size of the file name extension key</param>
        /// 
        /// <returns>A populated <see cref="KeyParams"/> class</returns>
        public KeyParams GetKeyParams(int KeySize, int IVSize = 0, int IKMSize = 0, int ExtKey = 0)
        {
            KeyParams kp = new KeyParams();

            if (KeySize > 0)
                kp.Key = Generate(KeySize);
            if (IVSize > 0)
                kp.IV = Generate(IVSize);
            if (IKMSize > 0)
                kp.IKM = Generate(IKMSize);
            if (ExtKey > 0)
                kp.ExtKey = Generate(ExtKey);

            return kp;
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            byte[] rand = Generate(Data.Length);
            Buffer.BlockCopy(rand, 0, Data, 0, rand.Length);
        }

        /// <summary>
        /// Return an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            return Generate(Size);
        }

        /// <summary>
        /// Reset the seed <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">Seed Generator</see> and the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engines
        /// </summary>
        public void Reset()
        {
            if (m_seedEngine != null)
            {
                m_seedEngine.Dispose();
                m_seedEngine = null;
            }
            m_seedEngine = SeedGeneratorFromName.GetInstance(SeedEngine);

            // reset hash engine
            if (m_hashEngine != null)
            {
                m_hashEngine.Dispose();
                m_hashEngine = null;
            }
            m_hashEngine = DigestFromName.GetInstance(HashEngine);

            // if absent, generate the initial counter
		    if (m_ctrLength == 0)
		    {
                if (m_hashEngine.BlockSize < 72)
                    m_ctrLength = CTRDEF_SIZE;
                else
                    m_ctrLength = CTRMAX_SIZE;

                m_ctrVector = new byte[m_ctrLength];

                using (CSPRsg pool =  new CSPRsg())
                    m_ctrVector = pool.GetBytes(m_ctrLength);
		    }
        }
        #endregion

        #region Private Methods
        private byte[] Generate(int Size)
        {
            byte[] key = new byte[Size];

            // get the first block
            byte[] rand = GetBlock();
            int blockSize = rand.Length;

            if (Size < blockSize)
            {
                Buffer.BlockCopy(rand, 0, key, 0, Size);
            }
            else
            {
                // copy first block
                Buffer.BlockCopy(rand, 0, key, 0, blockSize);

                int offset = blockSize;
                int alnSize = Size - (Size % blockSize);

                // fill the key array
                while (offset < alnSize)
                {
                    Buffer.BlockCopy(GetBlock(), 0, key, offset, blockSize);
                    offset += blockSize;
                }

                // process unaligned block
                if (alnSize < Size)
                    Buffer.BlockCopy(GetBlock(), 0, key, offset, Size - offset);
            }

            return key;
        }

        /// <remarks>
        /// Create keying material using a two stage generator
        /// </remarks>
        private byte[] GetBlock()
        {
            // generate seed; 2x input block size per NIST sp800-90b.

            // since the generator has already been initialized, so long as the sum extraction length is less
            // than the generators maximum output length, using unique seed material on each key is worth the computational expense.
            byte[] seed = m_seedEngine.GetBytes((m_hashEngine.BlockSize * 2) - m_ctrLength);
            // rotate the counter at 32 bit intervals
            Rotate(m_ctrVector);
            // prepend the counter to the seed
            seed = ArrayUtils.Concat(m_ctrVector, seed);

            // special case for sha-2
            if (m_dgtType == Digests.SHA256 || m_dgtType == Digests.SHA512)
            {
                // hmac key size is digest hash size: rfc 2104
                byte[] key = m_seedEngine.GetBytes(m_hashEngine.DigestSize);

                // set hmac to *not* dispose of underlying digest
                using (HMAC mac = new HMAC(m_hashEngine, key, false))
                    return mac.ComputeMac(seed);
            }
            else
            {
                // other implemented digests do not require hmac
                return m_hashEngine.ComputeHash(seed);
            }
        }

        /// <remarks>
        /// Convert to big endian integers, increment and convert back
        /// </remarks>
        private void Rotate(byte[] Counter)
        {
            // rotate the counter at 32 or 64 bit intervals
            if (RotationalAlignment == CounterAlignmentSizes.RAP32)
            {
                for (int i = 0; i < Counter.Length; i += 4)
                    IntUtils.Be32ToBytes(IntUtils.BytesToBe32(Counter, i) + 1, Counter, i);
            }
            else
            {
                for (int i = 0; i < Counter.Length; i += 8)
                    IntUtils.Be64ToBytes(IntUtils.BytesToBe64(Counter, i) + 1, Counter, i);
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
                    if (m_ctrVector != null)
                    {
                        Array.Clear(m_ctrVector, 0, m_ctrVector.Length);
                        m_ctrVector = null;
                    }
                    if (m_hashEngine != null)
                    {
                        m_hashEngine.Dispose();
                        m_hashEngine = null;
                    }
                    if (m_seedEngine != null)
                    {
                        m_seedEngine.Dispose();
                        m_seedEngine = null;
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
