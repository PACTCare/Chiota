#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// Creates, reads and writes parameter settings for MPKCEncrypt.
    /// <para>Predefined parameter sets are available and new ones can be created as well.
    /// These predefined settings are accessable through the <see cref="MPKCParamSets"/> class</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (MPKCParameters mp = new MPKCParameters(new byte[] { 1, 1, 11, 1 }, 11, 40, McElieceCiphers.Fujisaki, Digests.SHA256))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCEncrypt"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>MPKC Parameter Description:</description>
    /// <list type="table">
    /// <item><description><c>OId</c> - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</description></item>
    /// <item><description><c>M</c> - The degree of the finite field GF(2^m).</description></item>
    /// <item><description><c>T</c> - The error correction capability of the code.</description></item>
    /// <item><description><c>Engine</c> - The McEliece CCA2 cipher engine.</description></item>
    /// <item><description><c>Digest</c> - The digest used by the cipher engine.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: <a href="http://cacr.uwaterloo.ca/hac/about/chap8.pdf">Chapter 8</a></description></item>
    /// <item><description>Selecting Parameters for <a href="https://eprint.iacr.org/2010/271.pdf">Secure McEliece-based Cryptosystems</a></description></item>
    /// <item><description>Weak keys in the <a href="http://perso.univ-rennes1.fr/pierre.loidreau/articles/ieee-it/Cles_Faibles.pdf">McEliece Public-Key Crypto System</a></description></item>
    /// <item><description><a href="http://binary.cr.yp.to/mcbits-20130616.pdf">McBits</a>: fast constant-time code-based cryptography: </description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> versions McEliece implementation.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCParameters : IAsymmetricParameters
    {
        #region Constants
        // The default extension degree
        private const int DEFAULT_M = 11;
        // The default error correcting capability
        private const int DEFAULT_T = 50;
        private const int OID_SIZE = 4;
        private const string ALG_NAME = "MPKCParameters";
        #endregion

        #region Fields
        private int m_M;
        private int m_T;
        private int m_N;
        private byte[] m_oId = new byte[OID_SIZE];
        private int m_fieldPoly;
        private bool m_isDisposed = false;
        private Digests m_dgtEngineType = Digests.SHA256;
        private Prngs m_rndEngineType = Prngs.CTRPrng;
        private CCA2Ciphers m_cca2Engine = CCA2Ciphers.Pointcheval;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Parameters name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// The cipher engine used for encryption
        /// </summary>
        public CCA2Ciphers CCA2Engine
        {
            get { return m_cca2Engine; }
            private set { m_cca2Engine = value; }
        }

        /// <summary>
        /// The digest engine used to power CCA2 variants
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid digest is specified</exception>
        public Digests Digest
        {
            get { return m_dgtEngineType; }
            private set
            {
                if (value == Digests.Skein1024)
                    throw new CryptoAsymmetricException("MPKCParameters:Digest", "Only 512 and 256 bit Digests are supported!", new ArgumentException());

                m_dgtEngineType = value;
            }
        }

        /// <summary>
        /// Returns the field polynomial
        /// </summary>
        public int FieldPolynomial
        {
            get { return m_fieldPoly; }
        }

        /// <summary>
        /// Returns the extension degree of the finite field GF(2^m)
        /// </summary>
        public int M
        {
            get { return m_M; }
        }

        /// <summary>
        /// Returns the length of the code m_maxPlainText = (((MPKCPublicKey)AsmKey).K >> 3);
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// Get: Three bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return m_oId; }
            private set { m_oId = value; }
        }

        /// <summary>
        /// The cipher Prng
        /// </summary>
        public Prngs RandomEngine
        {
            get { return m_rndEngineType; }
            private set { m_rndEngineType = value; }
        }

        /// <summary>
        /// Return the error correction capability of the code
        /// </summary>
        public int T
        {
            get { return m_T; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Set the default parameters: extension degree
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The prng used by the cipher engine</param>
        public MPKCParameters(byte[] OId, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng) :
            this(OId, DEFAULT_M, DEFAULT_T)
        {
            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="Keysize">The length of a Goppa code</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the OId is invalid, or <c>keysize &lt; 1</c></exception>
        public MPKCParameters(byte[] OId, int Keysize, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (Keysize < 1)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "The key size must be positive!", new ArgumentException());
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.McEliece, new ArgumentException()));

            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;
            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            m_M = 0;
            m_N = 1;

            while (m_N < Keysize)
            {
                m_N <<= 1;
                m_M++;
            }
            m_T = m_N >> 1;
            m_T /= m_M;

            m_fieldPoly = PolynomialRingGF2.GetIrreduciblePolynomial(m_M);
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="M">The degree of the finite field GF(2^m)</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the OId is invalid or; <c>m &lt; 1</c>, <c>m &gt; 32</c>, <c>t &lt; 0</c> or <c>t &gt; n</c></exception>
        public MPKCParameters(byte[] OId, int M, int T, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.McEliece, new ArgumentException()));
            if (M < 1)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M must be positive!", new ArgumentException());
            if (M > 32)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M is too large!", new ArgumentOutOfRangeException());

            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            m_M = M;
            m_N = 1 << M;

            if (T < 0)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be positive!", new ArgumentException());
            if (T > N)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be less than n = 2^m!", new ArgumentOutOfRangeException());

            m_T = T;
            m_fieldPoly = PolynomialRingGF2.GetIrreduciblePolynomial(M);
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="M">The degree of the finite field GF(2^m)</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="FieldPoly">The field polynomial</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the OId is invalid or; <c>t &lt; 0</c>, <c>t &gt; n</c>, or <c>poly</c> is not an irreducible field polynomial</exception>
        public MPKCParameters(byte[] OId, int M, int T, int FieldPoly, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.McEliece, new ArgumentException()));
            if (M < 1)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M must be positive!", new ArgumentException());
            if (M > 32)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M is too large!", new ArgumentOutOfRangeException());

            m_M = M;
            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            m_N = 1 << M;
            m_T = T;

            if (T < 0)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be positive!", new ArgumentException());
            if (T > N)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be less than n = 2^m!", new ArgumentOutOfRangeException());

            if ((PolynomialRingGF2.Degree(FieldPoly) == M) && (PolynomialRingGF2.IsIrreducible(FieldPoly)))
                m_fieldPoly = FieldPoly;
            else
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "Polynomial is not a field polynomial for GF(2^m)", new InvalidDataException());
        }
        
        /// <summary>
        /// Builds a parameter set from an encoded input stream
        /// </summary>
        /// 
        /// <param name="ParamStream">Stream containing a parameter set</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public MPKCParameters(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                m_oId = reader.ReadBytes(OID_SIZE);
                m_cca2Engine = (CCA2Ciphers)reader.ReadInt32();
                m_dgtEngineType = (Digests)reader.ReadInt32();
                m_rndEngineType = (Prngs)reader.ReadInt32();
                m_M = reader.ReadInt32();
                m_T = reader.ReadInt32();
                m_fieldPoly = reader.ReadInt32();
                m_N = 1 << M;
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCParameters:CTor", "The stream could not be read!", ex);
            }
        }

        /// <summary>
        /// Builds a parameter set from an encoded byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">Byte array containing a parameter set</param>
        public MPKCParameters(byte[] ParamArray) :
            this(new MemoryStream(ParamArray))
        {
        }

        private MPKCParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read an encoded Parameter set from a byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">The byte array containing the parameters</param>
        /// 
        /// <returns>An initialized MPKCParameters class</returns>
        public static MPKCParameters From(byte[] ParamArray)
        {
            return new MPKCParameters(ParamArray);
        }

        /// <summary>
        /// Read an encoded Parameters set from a Stream
        /// </summary>
        /// 
        /// <param name="ParamStream">The Stream containing the encoded Parameter set</param>
        /// 
        /// <returns>An initialized MPKCParameters class</returns>
        public static MPKCParameters From(Stream ParamStream)
        {
            return new MPKCParameters(ParamStream);
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded byte array
        /// </summary>
        /// 
        /// <returns>McElieceParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded Stream
        /// </summary>
        /// 
        /// <returns>McElieceParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(OId);
            writer.Write((int)CCA2Engine);
            writer.Write((int)Digest);
            writer.Write((int)RandomEngine);
            writer.Write(M);
            writer.Write(T);
            writer.Write(FieldPolynomial);
            writer.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes the MPKCParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the MPKCParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if The output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("MPKCParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the MPKCParameters to a Stream
        /// </summary>
        /// 
        /// <param name="Output">The Output stream receiving the encoded Parameters</param>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException e)
            {
                throw new CryptoAsymmetricException(e.Message);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * (int)Digest;
            hash += 31 * (int)CCA2Engine;
            hash += 31 * (int)RandomEngine;
            hash += 31 * M;
            hash += 31 * N;
            hash += 31 * T;
            hash += 31 * FieldPolynomial;

            return hash;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null && this != null)
                return false;

            MPKCParameters other = (MPKCParameters)Obj;
            if (Digest != other.Digest)
                return false;
            if (CCA2Engine != other.CCA2Engine)
                return false;
            if (RandomEngine != other.RandomEngine)
                return false;
            if (M != other.M)
                return false;
            if (N != other.N)
                return false;
            if (T != other.T)
                return false;
            if (FieldPolynomial != other.FieldPolynomial)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this McElieceParameters instance
        /// </summary>
        /// 
        /// <returns>The McElieceParameters copy</returns>
        public object Clone()
        {
            return new MPKCParameters(m_oId, M, T, FieldPolynomial, m_cca2Engine, m_dgtEngineType, m_rndEngineType);
        }

        /// <summary>
        /// Create a deep copy of this MPKCParameters instance
        /// </summary>
        /// 
        /// <returns>The MPKCParameters copy</returns>
        public object DeepCopy()
        {
            return new MPKCParameters(ToStream());
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
                    if (m_oId != null)
                    {
                        Array.Clear(m_oId, 0, m_oId.Length);
                        m_oId = null;
                    }
                    m_N = 0;
                    m_M = 0;
                    m_T = 0;
                    m_fieldPoly = 0;
                    m_cca2Engine = CCA2Ciphers.Fujisaki;
                    m_dgtEngineType = Digests.SHA256;
                    m_rndEngineType = Prngs.CTRPrng;
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
