#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Factory
{
    /// <summary>
    /// <h3>A helper class for generating cryptographically strong keying material.</h3>
    /// <para>Generates an array or a populated KeyParams class, using a definable Digest(Prng) dual stage generator.</para>
    /// 
    /// </summary>
    /// 
    /// <example>
    /// <description>Create an array of pseudo random keying material:</description>
    /// <code>
    /// byte[] rand;
    /// using (KeyGenerator gen = new KeyGenerator([Prng], [Digest]))
    ///     // generate pseudo random bytes
    ///     rand = gen.Generate(Size);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/11" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Assignable digests and Prng parameters added</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng ">VTDev.Libraries.CEXEngine.Crypto.Prng Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom ">VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>SHA-2 Generates key material using a two stage Hmac_k(Prng()) process.</description></item>
    /// <item><description>Blake<cite>Blake</cite>, Keccak<cite>Keccak</cite>, and Skein<cite>Skein</cite> also use a two stage generation method; Hash(Prng()).</description></item>
    /// <item><description>Prng can be any of the <see cref="Prngs"/> generators.</description></item>
    /// <item><description>Hash can be any of the <see cref="Digests"/> digests.</description></item>
    /// <item><description>Default Prng is CSPRng<cite>RNGCryptoServiceProvider</cite>, default digest is SHA512.</description></item>
    /// <item><description>Resources are disposed of automatically.</description></item>
    /// </list>
    /// </remarks>
    public sealed class KeyGenerator : IDisposable
    {
        #region Fields
        private bool _isDisposed = false;
        private IDigest _hashEngine;
        private IRandom _seedEngine;
        #endregion

        #region Properties
        private Prngs SeedEngine { get; set; }
        private Digests HashEngine { get; set; }
        #endregion

        #region Constructor
        /// <summary>
        /// <para>Initializes the class with default generators; SHA-2 512, and RNGCryptoServiceProvider</para>
        /// </summary>
        public KeyGenerator()
        {
            // default engines
            SeedEngine = Prngs.CSPRng;
            HashEngine = Digests.SHA512;

            // initialize the generators
            Reset();
        }

        /// <summary>
        /// Initialize the class and generators
        /// </summary>
        /// <param name="SeedEngine">The <see cref="Prngs">Prng</see> that supplies the key and seed material to the hash function</param>
        /// <param name="HashEngine">The <see cref="Digests">Digest</see> type used to create the pseudo random keying material</param>
        public KeyGenerator(Prngs SeedEngine, Digests HashEngine)
        {
            this.SeedEngine = SeedEngine;
            this.HashEngine = HashEngine;

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
        /// <param name="IVSize">Size of Optional IV in bytes</param>
        /// <param name="IKMSize">Size of Optional IKM in bytes</param>
        /// 
        /// <returns>A populated <see cref="KeyParams"/> class</returns>
        public KeyParams GetKeyParams(int KeySize, int IVSize = 0, int IKMSize = 0)
        {
            if (IVSize > 0 && IKMSize > 0)
                return new KeyParams(Generate(KeySize), Generate(IVSize), Generate(IKMSize));
            else if (IVSize > 0)
                return new KeyParams(Generate(KeySize), Generate(IVSize));
            else if (IKMSize > 0)
                return new KeyParams(Generate(KeySize), null, Generate(IKMSize));
            else
                return new KeyParams(Generate(KeySize));
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
        /// Reset the seed <see cref="Prngs">PRNG</see> and the <see cref="Digests">Digest</see> engines
        /// </summary>
        public void Reset()
        {

            if (_seedEngine != null)
            {
                _seedEngine.Dispose();
                _seedEngine = null;
            }

            // select the prng
            switch (SeedEngine)
            {
                case Prngs.BBSG:
                    _seedEngine = new BBSG();
                    break;
                case Prngs.CCG:
                    _seedEngine = new CCG();
                    break;
                case Prngs.MODEXPG:
                    _seedEngine = new MODEXPG();
                    break;
                case Prngs.QCG1:
                    _seedEngine = new QCG1();
                    break;
                case Prngs.QCG2:
                    _seedEngine = new QCG2();
                    break;
                default:
                    _seedEngine = new CSPRng();
                    break;
            }

            if (_hashEngine != null)
            {
                _hashEngine.Dispose();
                _hashEngine = null;
            }

            // select the digest
            switch (HashEngine)
            {
                case Digests.Blake256:
                    _hashEngine = new Blake256();
                    break;
                case Digests.Blake512:
                    _hashEngine = new Blake512();
                    break;
                case Digests.Keccak256:
                    _hashEngine = new Keccak256();
                    break;
                case Digests.Keccak512:
                    _hashEngine = new Keccak512();
                    break;
                case Digests.SHA256:
                    _hashEngine = new SHA256();
                    break;
                case Digests.Skein256:
                    _hashEngine = new Skein256();
                    break;
                case Digests.Skein512:
                    _hashEngine = new Skein512();
                    break;
                case Digests.Skein1024:
                    _hashEngine = new Skein1024();
                    break;
                default:
                    _hashEngine = new SHA512();
                    break;
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
            // generate seed; 2x input block per NIST sp800-90b
            byte[] seed = _seedEngine.GetBytes((_hashEngine.BlockSize * 2));

            if (_hashEngine.GetType().Equals(typeof(SHA512)) || _hashEngine.GetType().Equals(typeof(SHA256)))
            {
                // hmac key size is digest hash size: rfc 2104
                byte[] key = _seedEngine.GetBytes(_hashEngine.DigestSize);

                // set hmac to *not* dispose of underlying digest
                using (HMAC mac = new HMAC(_hashEngine, key, false))
                    return mac.ComputeMac(seed);
            }
            else
            {
                // other implemented digests do not require hmac
                return _hashEngine.ComputeHash(seed);
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
                    if (_hashEngine != null)
                    {
                        _hashEngine.Dispose();
                        _hashEngine = null;
                    }
                    if (_seedEngine != null)
                    {
                        _seedEngine.Dispose();
                        _seedEngine = null;
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
