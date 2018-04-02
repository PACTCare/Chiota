#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Tools;
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
        SIMPLE,
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
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.0.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.NTRUEncrypt">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU NTRUEncrypt Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>NTRU Parameter Description:</h4></description>
    /// <list type="table">
    /// <item><description><c>OId</c> - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The NTRU family must be <c>2</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</description></item>
    /// <item><description><c>N</c> - Degree Parameter. A positive integer. The associated NTRU lattice has dimension 2N.</description></item>
    /// <item><description><c>q</c> - Large Modulus. A positive integer. The associated NTRU lattice is a convolution modular lattice of modulus q.</description></item>
    /// <item><description><c>p</c> - Small Modulus. An integer or a polynomial.</description></item>
    /// <item><description><c>Df, Dg</c> - Private Key Spaces. Sets of small polynomials from which the private keys are selected.</description></item>
    /// <item><description><c>Dm</c> - Plaintext Space. Set of polynomials that represent encryptable messages.</description></item>
    /// <item><description><c>Dr</c> - Blinding Value Space. Set of polynomials from which the temporary blinding value used during encryption is selected.</description></item>
    /// <item><description><c>Center</c> - Centering Method. A means of performing mod q reduction on decryption.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NTRU: A Ring Based Public Key Crypto System<cite>NTRU Crypto</cite>.</description></item>
    /// <item><description>Optimizations for NTRU<cite>NTRU Optimizations</cite>.</description></item>
    /// <item><description>Adaptive Key Recovery Attacks on NTRU-based Somewhat Homomorphic Encryption Schemes<cite>NTRU Adaptive</cite>.</description></item>
    /// <item><description>Efficient Embedded Security Standards (EESS)<cite>NTRU EESS</cite>.</description></item>
    /// <item><description>Practical lattice-based cryptography: NTRUEncrypt and NTRUSign<cite>NTRU Practical</cite>.</description></item>
    /// <item><description>NTRU Cryptosystems Technical Report<cite>NTRU Technical</cite>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent java project NTRU Encrypt by Tim Buktu: <see href="https://github.com/tbuktu/ntru/description">Release 1.2</see>, and
    /// the NTRUOpenSourceProject/ntru-crypto project provided by Security Innovation, Inc <see href="https://github.com/NTRUOpenSourceProject/ntru-crypto">NTRU Encrypt</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class NTRUParameters : IAsymmetricParameters
    {
        #region Constants
        private const int OID_SIZE = 4;
        private const string ALG_NAME = "NTRUParameters";
        #endregion

        #region Fields
        private int _N;
        private int _Q;
        private int _cBits;
        private int _Db;
        private int _DF;
        private int _DF1;
        private int _DF2;
        private int _DF3;
        private int _Dm0;
        private int _DR;
        private int _DR1;
        private int _DR2;
        private int _DR3;
        private bool _fastFp;
        private bool _hashSeed;
        private int _length;
        private int _maxM1;
        private int _msgMax;
        private Digests _dgtEngineType;
        private int _minIGFHashCalls;
        private int _minMGFHashCalls;
        private byte[] _oId = new byte[OID_SIZE];
        private TernaryPolynomialType _polyType;
        private Prngs _rndEngineType;
        private bool _sparseMode;
        private bool _isDisposed = false;
        private int _bufferLenTrits;
        internal int BufferLenBits;
        internal int Dg;
        internal int PkLen;
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
            get { return _N; }
        }

        /// <summary>
        /// Get: The big q Modulus
        /// </summary>
        public int Q
        {
            get { return _Q; }
        }

        /// <summary>
        /// Get: The number of bits in candidate for deriving an index in IGF-2
        /// </summary>
        public int CBits
        {
            get { return _cBits; }
        }

        /// <summary>
        /// Get: Number of random bits to prepend to the message; should be a multiple of 8
        /// </summary>
        public int Db
        {
            get { return _Db; }
        }

        /// <summary>
        /// Get: Number of ones in the private polynomial <c>f</c>
        /// </summary>
        public int DF
        {
            get { return _DF; }
        }

        /// <summary>
        /// Get/Set: Number of ones in the private polynomial <c>f1</c>; Product form of Df
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DF1
        {
            get { return _DF1; }
            set { _DF1 = value; }
        }

        /// <summary>
        /// Get/Set: Number of ones in the private polynomial <c>f2</c>; Product form of Df
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DF2
        {
            get { return _DF2; }
            set { _DF2 = value; }
        }

        /// <summary>
        /// Get/Set: Number of ones in the private polynomial <c>f3</c>; Product form of Df
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DF3
        {
            get { return _DF3; }
            set { _DF3 = value; }
        }

        /// <summary>
        /// Get: Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m</c> in the last encryption step
        /// </summary>
        public int Dm0
        {
            get { return _Dm0; }
        }

        /// <summary>
        /// Get: Blinding Value Space
        /// </summary>
        public int DR
        {
            get { return _DR; }
        }

        /// <summary>
        /// Get/Set: Blinding Value Space <c>dr1</c>; Product form of Dr
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DR1
        {
            get { return _DR1; }
            set { _DR1 = value; }
        }

        /// <summary>
        /// Get/Set: Blinding Value Space <c>dr2</c>; Product form of Dr
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DR2
        {
            get { return _DR2; }
            set { _DR2 = value; }
        }

        /// <summary>
        /// Get/Set: Blinding Value Space <c>dr3</c>; Product form of Dr
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public int DR3
        {
            get { return _DR3; }
            set { _DR3 = value; }
        }

        /// <summary>
        /// Get/Set: Whether <c>F=1+p*F</c> for a ternary <c>F</c> (true) or <c>F</c> is ternary (false)
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public bool FastFp
        {
            get { return _fastFp; }
            set { _fastFp = value; }
        }

        /// <summary>
        /// Get: Whether to hash the seed in the MGF first (true), or use the seed directly (false)
        /// </summary>
        public bool HashSeed
        {
            get { return _hashSeed; }
        }

        /// <summary>
        /// Get: Used in message length calculation
        /// </summary>
        internal int Length
        {
            get { return _length; }
        }

        /// <summary>
        /// Get: Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. 
        /// <para>Values greater than zero cause the constant coefficient of the message to always be zero.</para>
        /// </summary>
        public int MaxM1
        {
            get { return _maxM1; }
        }

        /// <summary>
        /// Get: The maximum  length of a plaintext message in bytes
        /// </summary>
        public int MessageMax
        {
            get { return _msgMax; }
        }

        /// <summary>
        /// Get/Set: The Message Digest engine to use; default is SHA512
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public Digests Digest
        {
            get { return _dgtEngineType; }
            set { _dgtEngineType = value; }
        }

        /// <summary>
        /// Get: Minimum number of hash calls for the IGF to make
        /// </summary>
        public int MinIGFHashCalls
        {
            get { return _minIGFHashCalls; }
        }

        /// <summary>
        /// Get: Minimum number of calls to generate the masking polynomial
        /// </summary>
        public int MinMGFHashCalls
        {
            get { return _minMGFHashCalls; }
        }

        /// <summary>
        /// Get: Three bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return _oId; }
            private set { _oId = value; }
        }

        /// <summary>
        /// Get/Set: The polynomial type
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public TernaryPolynomialType PolyType
        {
            get { return _polyType; }
            set { _polyType = value; }
        }

        /// <summary>
        /// Get/Set: The pseudo random generator engine to use; default is CSPRng
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        public Prngs RandomEngine
        {
            get { return _rndEngineType; }
            set { _rndEngineType = value; }
        }

        /// <summary>
        /// Whether to treat ternary polynomials as sparsely populated; SparseTernaryPolynomial vs DenseTernaryPolynomialinternal
        /// </summary>
        public bool Sparse
        {
            get { return _sparseMode; }
            set { _sparseMode = value; }
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
            _N = N;
            _Q = Q;
            _DF = Df;
            _Db = Db;
            _Dm0 = Dm0;
            _maxM1 = MaxM1;
            _cBits = CBits;
            _minIGFHashCalls = MinIGFHashCalls;
            _minMGFHashCalls = MinMGFHashCalls;
            _hashSeed = HashSeed;
            _sparseMode = Sparse;
            _fastFp = FastFp;
            _polyType = TernaryPolynomialType.SIMPLE;
            _dgtEngineType = Digest;
            _rndEngineType = Random;

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
            _N = N;
            _Q = Q;
            _DF1 = Df1;
            _DF2 = Df2;
            _DF3 = Df3;
            _Db = Db;
            _Dm0 = Dm0;
            _maxM1 = MaxM1;
            _cBits = CBits;
            _minIGFHashCalls = MinIGFHashCalls;
            _minMGFHashCalls = MinMGFHashCalls;
            _hashSeed = HashSeed;
            _sparseMode = Sparse;
            _fastFp = FastFp;
            _polyType = TernaryPolynomialType.PRODUCT;
            _dgtEngineType = Digest;
            _rndEngineType = Random;

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

                _oId = new byte[OID_SIZE];
                reader.Read(_oId, 0, _oId.Length);
                _N = reader.ReadInt32();
                _Q = reader.ReadInt32();
                _DF = reader.ReadInt32();
                _DF1 = reader.ReadInt32();
                _DF2 = reader.ReadInt32();
                _DF3 = reader.ReadInt32();
                _Db = reader.ReadInt32();
                _Dm0 = reader.ReadInt32();
                _maxM1 = reader.ReadInt32();
                _cBits = reader.ReadInt32();
                _minIGFHashCalls = reader.ReadInt32();
                _minMGFHashCalls = reader.ReadInt32();
                _hashSeed = reader.ReadBoolean();
                _sparseMode = reader.ReadBoolean();
                _fastFp = reader.ReadBoolean();
                _polyType = (TernaryPolynomialType)reader.ReadInt32();
                _dgtEngineType = (Digests)reader.ReadInt32();
                _rndEngineType = (Prngs)reader.ReadInt32();

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
            writer.Write(_oId);
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
            writer.Write(_minIGFHashCalls);
            writer.Write(_minMGFHashCalls);
            writer.Write(HashSeed);
            writer.Write(_sparseMode);
            writer.Write(FastFp);
            writer.Write((int)_polyType);
            writer.Write((int)_dgtEngineType);
            writer.Write((int)_rndEngineType);
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
            _DR = DF;
            _DR1 = DF1;
            _DR2 = DF2;
            _DR3 = DF3;
            Dg = N / 3;
            _length = 1;   // ceil(log2(maxMsgLenBytes))

            if (MaxM1 > 0)
                _msgMax = (N - 1) * 3 / 2 / 8 - _length - Db / 8;   // only N-1 coeffs b/c the constant coeff is not used
            else
                _msgMax = N * 3 / 2 / 8 - _length - Db / 8;

            BufferLenBits = (N * 3 / 2 + 7) / 8 * 8 + 1;
            _bufferLenTrits = N - 1;
            PkLen = Db;
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
            int prime = 31;
            int result = 1;

            result = prime * result + N;
            result = prime * result + BufferLenBits;
            result = prime * result + _bufferLenTrits;
            result = prime * result + CBits;
            result = prime * result + Db;
            result = prime * result + DF;
            result = prime * result + DF1;
            result = prime * result + DF2;
            result = prime * result + DF3;
            result = prime * result + Dg;
            result = prime * result + Dm0;
            result = prime * result + MaxM1;
            result = prime * result + DR;
            result = prime * result + DR1;
            result = prime * result + DR2;
            result = prime * result + DR3;
            result = prime * result + (FastFp ? 1231 : 1237);
            result = prime * result + Digest.GetHashCode();
            result = prime * result + RandomEngine.GetHashCode();
            result = prime * result + (HashSeed ? 1231 : 1237);
            result = prime * result + Length;
            result = prime * result + MessageMax;
            result = prime * result + MinMGFHashCalls;
            result = prime * result + MinIGFHashCalls;
            result = prime * result + OId.GetHashCode();
            result = prime * result + PkLen;
            result = prime * result + PolyType.GetHashCode();
            result = prime * result + Q;
            result = prime * result + (Sparse ? 1231 : 1237);

            return result;
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
            if (BufferLenBits != other.BufferLenBits)
                return false;
            if (_bufferLenTrits != other._bufferLenTrits)
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
            if (!Compare.AreEqual(OId, other.OId))
                return false;
            if (PkLen != other.PkLen)
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
            if (_polyType == TernaryPolynomialType.SIMPLE)
                return new NTRUParameters(_oId, _N, _Q, _DF, _Dm0, _maxM1, _Db, _cBits, _minIGFHashCalls, _minMGFHashCalls, _hashSeed, _sparseMode, _fastFp, _dgtEngineType, _rndEngineType);
            else
                return new NTRUParameters(_oId, _N, _Q, _DF1, _DF2, _DF3, _Dm0, _maxM1, _Db, _cBits, _minIGFHashCalls, _minMGFHashCalls, _hashSeed, _sparseMode, _fastFp, _dgtEngineType, _rndEngineType);
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    _N = 0;
                    _Q = 0;
                    _DF = 0;
                    _DF1 = 0;
                    _DF2 = 0;
                    _DF3 = 0;
                    _Db = 0;
                    _Dm0 = 0;
                    _maxM1 = 0;
                    _cBits = 0;
                    _minIGFHashCalls = 0;
                    _minMGFHashCalls = 0;
                    _hashSeed = false;
                    _fastFp = false;
                    _sparseMode = false;
                    _dgtEngineType = Digests.SHA512;
                    _rndEngineType = Prngs.CTRPrng;

                    if (_oId != null)
                    {
                        Array.Clear(_oId, 0, _oId.Length);
                        _oId = null;
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