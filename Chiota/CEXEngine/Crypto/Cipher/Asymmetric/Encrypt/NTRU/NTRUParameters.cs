#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// NTRU Encrypt in C# (NTRUSharp)
// Copyright (C) 2015 John Underhill
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
//
// Based on the java project NTRUEncrypt by Tim Buktu: <https://github.com/tbuktu/ntru> and the C version
// <https://github.com/NTRUOpenSourceProject/ntru-crypto> NTRUOpenSourceProject/ntru-crypto.
// NTRU is owned and patented by Security Innovations: <https://www.securityinnovation.com/products/encryption-libraries/ntru-crypto/>,
// authors and originators include; Jeffrey Hoffstein, Jill Pipher, and Joseph H. Silverman.
// 
// Implementation Details:
// An implementation of NTRU Encrypt in C#.
// Written by John Underhill, April 09, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU
{
    #region Enums
    /// <summary>
    /// TernaryPolynomialType enumeration
    /// </summary>
    public enum TernaryPolynomialType
    {
        /// <summary>
        /// Use Ternary type key
        /// </summary>
        SIMPLE = 0,
        /// <summary>
        /// Use Product form type key
        /// </summary>
        PRODUCT
    };
    #endregion

    /// <summary>
    /// Creates, reads and writes parameter settings for NtruEncrypt.
    /// <para>Predefined parameter sets are available and new ones can be created as well.
    /// These predefined settings are accessable through the <see cref="NTRUParamSets"/> class</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (NtruParameters np = new NtruParameters(new byte[] { 2, 1, 1, 63 }, 1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, true, false, Digests.SHA512))
    ///    np.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.NTRUEncrypt"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>NTRU Parameter Description:</description>
    /// <list type="table">
    /// <item><description><c>OId</c> - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The NTRU family must be <c>2</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</description></item>
    /// <item><description><c>N</c> - Degree Parameter. A positive integer. The associated NTRU lattice has dimension 2N.</description></item>
    /// <item><description><c>q</c> - Large Modulus. A positive integer. The associated NTRU lattice is a convolution modular lattice of modulus q.</description></item>
    /// <item><description><c>p</c> - Small Modulus. An integer or a polynomial.</description></item>
    /// <item><description><c>Df, m_Dg</c> - Private Key Spaces. Sets of small polynomials from which the private keys are selected.</description></item>
    /// <item><description><c>Dm</c> - Plaintext Space. Set of polynomials that represent encryptable messages.</description></item>
    /// <item><description><c>Dr</c> - Blinding Value Space. Set of polynomials from which the temporary blinding value used during encryption is selected.</description></item>
    /// <item><description><c>Center</c> - Centering Method. A means of performing mod q reduction on decryption.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NTRU: A Ring Based <a href="http://binary.cr.yp.to/mcbits-20130616.pdf">Public Key Crypto System</a>.</description></item>
    /// <item><description><a href="https://www.securityinnovation.com/uploads/Crypto/TECH_ARTICLE_OPT.pdf">Optimizations</a> for NTRU.</description></item>
    /// <item><description>Adaptive Key Recovery Attacks on NTRU-based Somewhat <a href="https://eprint.iacr.org/2015/127.pdf">Homomorphic Encryption Schemes</a>.</description></item>
    /// <item><description>Efficient Embedded Security Standards <a href="http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf">EESS</a>.</description></item>
    /// <item><description>Practical lattice-based cryptography: <a href="https://www.securityinnovation.com/uploads/Crypto/lll25.pdf">NTRUEncrypt and NTRUSign</a>.</description></item>
    /// <item><description>NTRU Cryptosystems <a href="https://www.securityinnovation.com/uploads/Crypto/NTRUTech016.pdf">Technical Report</a>.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent java project NTRU Encrypt by Tim Buktu: <a href="https://github.com/tbuktu/ntru/description">Release 1.2</a>, and
    /// the NTRUOpenSourceProject/ntru-crypto project provided by Security Innovation, Inc <a href="https://github.com/NTRUOpenSourceProject/ntru-crypto">NTRU Encrypt</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class NTRUParameters : IAsymmetricParameters
    {
        #region Constants
        private const int OID_SIZE = 4;
        private const string ALG_NAME = "NTRUParameters";
        #endregion

        #region Fields
        private int m_N;
        private int m_Q;
        private int m_cBits;
        private int m_Db;
        private int m_DF;
        private int m_DF1;
        private int m_DF2;
        private int m_DF3;
        private int m_Dm0;
        private int m_DR;
        private int m_DR1;
        private int m_DR2;
        private int m_DR3;
        private bool m_fastFp;
        private bool m_hashSeed;
        private int m_length;
        private int m_maxM1;
        private int m_msgMax;
        private Digests m_dgtEngineType;
        private int m_minIGFHashCalls;
        private int m_minMGFHashCalls;
        private byte[] m_oId = new byte[OID_SIZE];
        private TernaryPolynomialType m_polyType;
        private Prngs m_rndEngineType;
        private bool m_sparseMode;
        private bool m_isDisposed = false;
        private int m_bufferLenTrits;
        internal int m_bufferLenBits;
        internal int Dg;
        internal int m_PkLen;
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
        /// Get: The ring dimension; the number of polynomial coefficients
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// Get: The big q Modulus
        /// </summary>
        public int Q
        {
            get { return m_Q; }
        }

        /// <summary>
        /// Get: The number of bits in candidate for deriving an index in IGF-2
        /// </summary>
        public int CBits
        {
            get { return m_cBits; }
        }

        /// <summary>
        /// Get/Set: Number of random bits to prepend to the message; should be a multiple of 8
        /// </summary>
        public int Db
        {
            get { return m_Db; }
            set { m_Db = value; }
        }

        /// <summary>
        /// Get: Number of ones in the private polynomial <c>f</c>
        /// </summary>
        public int DF
        {
            get { return m_DF; }
        }

        /// <summary>
        /// Get/Set: Number of ones in the private polynomial <c>f1</c>; Product form of Df
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DF1
        {
            get { return m_DF1; }
            set { m_DF1 = value; }
        }

        /// <summary>
        /// Get/Set: Number of ones in the private polynomial <c>f2</c>; Product form of Df
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DF2
        {
            get { return m_DF2; }
            set { m_DF2 = value; }
        }

        /// <summary>
        /// Get/Set: Number of ones in the private polynomial <c>f3</c>; Product form of Df
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DF3
        {
            get { return m_DF3; }
            set { m_DF3 = value; }
        }

        /// <summary>
        /// Get: Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m</c> in the last encryption step
        /// </summary>
        public int Dm0
        {
            get { return m_Dm0; }
        }

        /// <summary>
        /// Get: Blinding Value Space
        /// </summary>
        public int DR
        {
            get { return m_DR; }
        }

        /// <summary>
        /// Get/Set: Blinding Value Space <c>dr1</c>; Product form of Dr
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DR1
        {
            get { return m_DR1; }
            set { m_DR1 = value; }
        }

        /// <summary>
        /// Get/Set: Blinding Value Space <c>dr2</c>; Product form of Dr
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DR2
        {
            get { return m_DR2; }
            set { m_DR2 = value; }
        }

        /// <summary>
        /// Get/Set: Blinding Value Space <c>dr3</c>; Product form of Dr
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DR3
        {
            get { return m_DR3; }
            set { m_DR3 = value; }
        }

        /// <summary>
        /// Get/Set: Whether <c>F=1+p*F</c> for a ternary <c>F</c> (true) or <c>F</c> is ternary (false)
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public bool FastFp
        {
            get { return m_fastFp; }
            set { m_fastFp = value; }
        }

        /// <summary>
        /// Get: Whether to hash the seed in the MGF first (true), or use the seed directly (false)
        /// </summary>
        public bool HashSeed
        {
            get { return m_hashSeed; }
        }

        /// <summary>
        /// Get: Used in message length calculation
        /// </summary>
        internal int Length
        {
            get { return m_length; }
        }

        /// <summary>
        /// Get: Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. 
        /// <para>Values greater than zero cause the constant coefficient of the message to always be zero.</para>
        /// </summary>
        public int MaxM1
        {
            get { return m_maxM1; }
        }

        /// <summary>
        /// Get: The maximum length of a plaintext message in bytes
        /// </summary>
        public int MessageMax
        {
            get { return m_msgMax; }
        }

        /// <summary>
        /// Get/Set: The Message Digest engine to use; default is SHA512
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public Digests Digest
        {
            get { return m_dgtEngineType; }
            set { m_dgtEngineType = value; }
        }

        /// <summary>
        /// Get/Set: Minimum number of hash calls for the IGF to make
        /// </summary>
        public int MinIGFHashCalls
        {
            get { return m_minIGFHashCalls; }
            set { m_minIGFHashCalls = value; }
        }

        /// <summary>
        /// Get/Set: Minimum number of calls to generate the masking polynomial
        /// </summary>
        public int MinMGFHashCalls
        {
            get { return m_minMGFHashCalls; }
            set { m_minMGFHashCalls = value; }
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
        /// Get/Set: The polynomial type
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public TernaryPolynomialType PolyType
        {
            get { return m_polyType; }
            set { m_polyType = value; }
        }

        /// <summary>
        /// Get/Set: The pseudo random generator engine to use; default is CSPPrng
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public Prngs RandomEngine
        {
            get { return m_rndEngineType; }
            set { m_rndEngineType = value; }
        }

        /// <summary>
        /// Whether to treat ternary polynomials as sparsely populated; SparseTernaryPolynomial vs DenseTernaryPolynomialinternal
        /// </summary>
        public bool Sparse
        {
            get { return m_sparseMode; }
            set { m_sparseMode = value; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a parameter set that uses ternary private keys (i.e. <c>PolyType=SIMPLE</c>)
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The NTRU family must be <c>2</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="N">The ring dimension; the number of polynomial coefficients</param>
        /// <param name="Q">The big Q Modulus</param>
        /// <param name="Df">Number of ones in the private polynomial <c>f</c></param>
        /// <param name="Dm0">Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m</c> in the last encryption step</param>
        /// <param name="MaxM1">Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.</param>
        /// <param name="Db">Number of random bits to prepend to the message; should be a multiple of 8</param>
        /// <param name="CBits">The number of bits in candidate for deriving an index in IGF-2</param>
        /// <param name="MinIGFHashCalls">Minimum number of hash calls for the IGF to make</param>
        /// <param name="MinMGFHashCalls">Minimum number of calls to generate the masking polynomial</param>
        /// <param name="HashSeed">Whether to hash the seed in the MGF first (true), or use the seed directly (false)</param>
        /// <param name="Sparse">Whether to treat ternary polynomials as sparsely populated; SparseTernaryPolynomial vs DenseTernaryPolynomial</param>
        /// <param name="FastFp">Whether <c>f=1+p*F</c> for a ternary <c>F</c> (true) or <c>f</c> is ternary (false)</param>
        /// <param name="Digest">The Message Digest engine to use; default is SHA512</param>
        /// <param name="Random">The pseudo random generator engine to use; default is CTRPrng</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Oid format is invalid</exception>
        public NTRUParameters(byte[] OId, int N, int Q, int Df, int Dm0, int MaxM1, int Db, int CBits, int MinIGFHashCalls, int MinMGFHashCalls,
            bool HashSeed, bool Sparse, bool FastFp, Digests Digest = Digests.SHA512, Prngs Random = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("NTRUParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.NTRU)
                throw new CryptoAsymmetricException("NTRUParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.NTRU, new ArgumentException()));

            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            m_N = N;
            m_Q = Q;
            m_DF = Df;
            m_Db = Db;
            m_Dm0 = Dm0;
            m_maxM1 = MaxM1;
            m_cBits = CBits;
            m_minIGFHashCalls = MinIGFHashCalls;
            m_minMGFHashCalls = MinMGFHashCalls;
            m_hashSeed = HashSeed;
            m_sparseMode = Sparse;
            m_fastFp = FastFp;
            m_polyType = TernaryPolynomialType.SIMPLE;
            m_dgtEngineType = Digest;
            m_rndEngineType = Random;

            Initialize();
        }

        /// <summary>
        /// Constructs a parameter set that uses product-form private keys (i.e. <c>PolyType=PRODUCT</c>).
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The NTRU family must be <c>2</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="N">N number of polynomial coefficients</param>
        /// <param name="Q">The big Q Modulus</param>
        /// <param name="Df1">Number of ones in the private polynomial <c>f1</c></param>
        /// <param name="Df2">Number of ones in the private polynomial <c>f2</c></param>
        /// <param name="Df3">Number of ones in the private polynomial <c>f3</c></param>
        /// <param name="Dm0">Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m'</c> in the last encryption step</param>
        /// <param name="MaxM1">Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.</param>
        /// <param name="Db">Number of random bits to prepend to the message; should be a multiple of 8</param>
        /// <param name="CBits">The number of bits in candidate for deriving an index in IGF-2</param>
        /// <param name="MinIGFHashCalls">Minimum number of hash calls for the IGF to make</param>
        /// <param name="MinMGFHashCalls">Minimum number of calls to generate the masking polynomial</param>
        /// <param name="HashSeed">Whether to hash the seed in the MGF first (true) or use the seed directly (false)</param>
        /// <param name="Sparse">Whether to treat ternary polynomials as sparsely populated SparseTernaryPolynomial vs DenseTernaryPolynomial</param>
        /// <param name="FastFp">Whether <c>F=1+p*F</c> for a ternary <c>F</c> (true) or <c>F</c> is ternary (false)</param>
        /// <param name="Digest">The Message Digest engine to use; default is SHA512</param>
        /// <param name="Random">The pseudo random generator engine to use; default is CTRPrng</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Oid format is invalid</exception>
        public NTRUParameters(byte[] OId, int N, int Q, int Df1, int Df2, int Df3, int Dm0, int MaxM1, int Db, int CBits, int MinIGFHashCalls, int MinMGFHashCalls,
            bool HashSeed, bool Sparse, bool FastFp, Digests Digest = Digests.SHA512, Prngs Random = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("NTRUParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.NTRU)
                throw new CryptoAsymmetricException("NTRUParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.NTRU, new ArgumentException()));

            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            m_N = N;
            m_Q = Q;
            m_DF1 = Df1;
            m_DF2 = Df2;
            m_DF3 = Df3;
            m_Db = Db;
            m_Dm0 = Dm0;
            m_maxM1 = MaxM1;
            m_cBits = CBits;
            m_minIGFHashCalls = MinIGFHashCalls;
            m_minMGFHashCalls = MinMGFHashCalls;
            m_hashSeed = HashSeed;
            m_sparseMode = Sparse;
            m_fastFp = FastFp;
            m_polyType = TernaryPolynomialType.PRODUCT;
            m_dgtEngineType = Digest;
            m_rndEngineType = Random;

            Initialize();
        }

        /// <summary>
        /// Builds a parameter set from an encoded input stream
        /// </summary>
        /// 
        /// <param name="ParamStream">Stream containing a parameter set</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public NTRUParameters(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);

                m_oId = new byte[OID_SIZE];
                reader.Read(m_oId, 0, m_oId.Length);
                m_N = reader.ReadInt32();
                m_Q = reader.ReadInt32();
                m_DF = reader.ReadInt32();
                m_DF1 = reader.ReadInt32();
                m_DF2 = reader.ReadInt32();
                m_DF3 = reader.ReadInt32();
                m_Db = reader.ReadInt32();
                m_Dm0 = reader.ReadInt32();
                m_maxM1 = reader.ReadInt32();
                m_cBits = reader.ReadInt32();
                m_minIGFHashCalls = reader.ReadInt32();
                m_minMGFHashCalls = reader.ReadInt32();
                m_hashSeed = reader.ReadBoolean();
                m_sparseMode = reader.ReadBoolean();
                m_fastFp = reader.ReadBoolean();
                m_polyType = (TernaryPolynomialType)reader.ReadInt32();
                m_dgtEngineType = (Digests)reader.ReadInt32();
                m_rndEngineType = (Prngs)reader.ReadInt32();

                Initialize();
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("NTRUParameters:CTor", "The stream could not be read!", ex);
            }
        }
        
        /// <summary>
        /// Builds a parameter set from an encoded byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">Byte array containing a parameter set</param>
        public NTRUParameters(byte[] ParamArray) :
            this(new MemoryStream(ParamArray))
        {
        }

        private NTRUParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUParameters()
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
        /// <returns>An initialized NTRUParameters class</returns>
        public static NTRUParameters From(byte[] ParamArray)
        {
            return new NTRUParameters(ParamArray);
        }

        /// <summary>
        /// Read an encoded Parameters set from a Stream
        /// </summary>
        /// 
        /// <param name="ParamStream">The Stream containing the encoded Parameter set</param>
        /// 
        /// <returns>An initialized NTRUParameters class</returns>
        public static NTRUParameters From(Stream ParamStream)
        {
            return new NTRUParameters(ParamStream);
        }

        /// <summary>
        /// Returns the length of a message after encryption with this parameter set
        /// <para>The length does not depend on the input size.</para>
        /// </summary>
        /// 
        /// <returns>The length in bytes</returns>
        public int GetOutputLength()
        {
            // ceil(log q)
            int logq = 32 - IntUtils.NumberOfLeadingZeros(Q - 1);
            return (N * logq + 7) / 8;
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded byte array
        /// </summary>
        /// 
        /// <returns>NtruParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded Stream
        /// </summary>
        /// 
        /// <returns>NtruParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(m_oId);
            writer.Write(N);
            writer.Write(Q);
            writer.Write(DF);
            writer.Write(DF1);
            writer.Write(DF2);
            writer.Write(DF3);
            writer.Write(Db);
            writer.Write(Dm0);
            writer.Write(MaxM1);
            writer.Write(CBits);
            writer.Write(m_minIGFHashCalls);
            writer.Write(m_minMGFHashCalls);
            writer.Write(HashSeed);
            writer.Write(m_sparseMode);
            writer.Write(FastFp);
            writer.Write((int)m_polyType);
            writer.Write((int)m_dgtEngineType);
            writer.Write((int)m_rndEngineType);
            writer.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes the NTRUParameters to a byte array
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
        /// Writes the NTRUParameters to a byte array
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
                throw new CryptoAsymmetricException("NTRUParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the NTRUParameters to a Stream
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
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("NTRUParameters:WriteTo", ex.Message, ex);
            }
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            m_DR = DF;
            m_DR1 = DF1;
            m_DR2 = DF2;
            m_DR3 = DF3;
            Dg = N / 3;
            m_length = 1;   // ceil(log2(maxMsgLenBytes))

            if (MaxM1 > 0)
                m_msgMax = (N - 1) * 3 / 2 / 8 - m_length - Db / 8;   // only N-1 coeffs b/c the constant coeff is not used
            else
                m_msgMax = N * 3 / 2 / 8 - m_length - Db / 8;

            m_bufferLenBits = (N * 3 / 2 + 7) / 8 * 8 + 1;
            m_bufferLenTrits = N - 1;
            m_PkLen = Db;
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
            int hash = 31 * N;
            hash += 31 * m_bufferLenBits;
            hash += 31 * m_bufferLenTrits;
            hash += 31 * CBits;
            hash += 31 * Db;
            hash += 31 * DF;
            hash += 31 * DF1;
            hash += 31 * DF2;
            hash += 31 * DF3;
            hash += 31 * Dg;
            hash += 31 * Dm0;
            hash += 31 * MaxM1;
            hash += 31 * DR;
            hash += 31 * DR1;
            hash += 31 * DR2;
            hash += 31 * DR3;
            hash += 31 * (FastFp ? 1231 : 1237);
            hash += 31 * (int)Digest;
            hash += 31 * (int)RandomEngine;
            hash += 31 * (HashSeed ? 1231 : 1237);
            hash += 31 * Length;
            hash += 31 * MessageMax;
            hash += 31 * MinMGFHashCalls;
            hash += 31 * MinIGFHashCalls;
            hash += ArrayUtils.GetHashCode(OId);
            hash += 31 * m_PkLen;
            hash += 31 * (int)PolyType;
            hash += 31 * Q;
            hash += 31 * (Sparse ? 1231 : 1237);

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
            if (Obj == null)
                return false;

            NTRUParameters other = (NTRUParameters)Obj;
            if (N != other.N)
                return false;
            if (m_bufferLenBits != other.m_bufferLenBits)
                return false;
            if (m_bufferLenTrits != other.m_bufferLenTrits)
                return false;
            if (CBits != other.CBits)
                return false;
            if (Db != other.Db)
                return false;
            if (DF != other.DF)
                return false;
            if (DF1 != other.DF1)
                return false;
            if (DF2 != other.DF2)
                return false;
            if (DF3 != other.DF3)
                return false;
            if (Dg != other.Dg)
                return false;
            if (Dm0 != other.Dm0)
                return false;
            if (MaxM1 != other.MaxM1)
                return false;
            if (DR != other.DR)
                return false;
            if (DR1 != other.DR1)
                return false;
            if (DR2 != other.DR2)
                return false;
            if (DR3 != other.DR3)
                return false;
            if (FastFp != other.FastFp)
                return false;
            if (!Digest.Equals(other.Digest))
                return false;
            if (!RandomEngine.Equals(other.RandomEngine))
                return false;
            if (HashSeed != other.HashSeed)
                return false;
            if (Length != other.Length)
                return false;
            if (MessageMax != other.MessageMax)
                return false;
            if (MinMGFHashCalls != other.MinMGFHashCalls)
                return false;
            if (MinIGFHashCalls != other.MinIGFHashCalls)
                return false;
            if (!Compare.IsEqual(OId, other.OId))
                return false;
            if (m_PkLen != other.m_PkLen)
                return false;
            if (!PolyType.Equals(other.PolyType))
                return false;
            if (Q != other.Q)
                return false;
            if (Sparse != other.Sparse)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this NTRUParameters instance
        /// </summary>
        /// 
        /// <returns>The NTRUParameters copy</returns>
        public object Clone()
        {
            if (m_polyType == TernaryPolynomialType.SIMPLE)
                return new NTRUParameters(m_oId, m_N, m_Q, m_DF, m_Dm0, m_maxM1, m_Db, m_cBits, m_minIGFHashCalls, m_minMGFHashCalls, m_hashSeed, m_sparseMode, m_fastFp, m_dgtEngineType, m_rndEngineType);
            else
                return new NTRUParameters(m_oId, m_N, m_Q, m_DF1, m_DF2, m_DF3, m_Dm0, m_maxM1, m_Db, m_cBits, m_minIGFHashCalls, m_minMGFHashCalls, m_hashSeed, m_sparseMode, m_fastFp, m_dgtEngineType, m_rndEngineType);
        }

        /// <summary>
        /// Create a deep copy of this NTRUParameters instance
        /// </summary>
        /// 
        /// <returns>The NTRUParameters copy</returns>
        public object DeepCopy()
        {
            return new NTRUParameters(ToStream());
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
                    m_N = 0;
                    m_Q = 0;
                    m_DF = 0;
                    m_DF1 = 0;
                    m_DF2 = 0;
                    m_DF3 = 0;
                    m_Db = 0;
                    m_Dm0 = 0;
                    m_maxM1 = 0;
                    m_cBits = 0;
                    m_minIGFHashCalls = 0;
                    m_minMGFHashCalls = 0;
                    m_hashSeed = false;
                    m_fastFp = false;
                    m_sparseMode = false;
                    m_dgtEngineType = Digests.SHA512;
                    m_rndEngineType = Prngs.CTRPrng;

                    if (m_oId != null)
                    {
                        Array.Clear(m_oId, 0, m_oId.Length);
                        m_oId = null;
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