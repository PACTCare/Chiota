#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
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
    /// <summary>
    /// A NTRU Private Key
    /// </summary>
    public sealed class NTRUPrivateKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "NTRUPrivateKey";
        #endregion

        #region Fields
        private bool m_fastFp;
        private bool m_isDisposed = false;
        private TernaryPolynomialType m_polyType;
        private bool m_sparse;
        private IntegerPolynomial m_FP;
        private int m_N;
        private int m_Q;
        private IPolynomial m_T;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Private key name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: The number of polynomial coefficients
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// Get: The big Q modulus
        /// </summary>
        public int Q
        {
            get { return m_Q; }
        }

        /// <summary>
        /// Get: PolyType type of the polynomial <c>T</c>
        /// </summary>
        internal TernaryPolynomialType PolyType
        {
            get { return m_polyType; }
        }

        /// <summary>
        /// Get/Set: The polynomial which determines the key: if <c>FastFp=true</c>, <c>F=1+3T</c>; otherwise, <c>F=T</c>
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        internal IPolynomial T
        {
            get { return m_T; }
            set { m_T = value; }
        }

        /// <summary>
        /// Get: Fp the inverse of <c>F</c>
        /// </summary>
        internal IntegerPolynomial FP
        {
            get { return m_FP; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new private key from a polynomial
        /// </summary>
        /// 
        /// <param name="T">The polynomial which determines the key: if <c>FastFp=true</c>, <c>f=1+3T</c>; otherwise, <c>f=T</c></param>
        /// <param name="FP">Fp the inverse of <c>f</c></param>
        /// <param name="N">The number of polynomial coefficients</param>
        /// <param name="Q">The big q modulus</param>
        /// <param name="Sparse">Sparse whether the polynomial <c>T</c> is sparsely or densely populated</param>
        /// <param name="FastFp">FastFp whether <c>FP=1</c></param>
        /// <param name="PolyType">PolyType type of the polynomial <c>T</c></param>
        internal NTRUPrivateKey(IPolynomial T, IntegerPolynomial FP, int N, int Q, bool Sparse, bool FastFp, TernaryPolynomialType PolyType)
        {
            m_T = T;
            m_FP = FP;
            m_N = N;
            m_Q = Q;
            m_sparse = Sparse;
            m_fastFp = FastFp;
            m_polyType = PolyType;
        }

        /// <summary>
        /// Reads a Private Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public NTRUPrivateKey(MemoryStream KeyStream)
        {
            BinaryReader dataStream = new BinaryReader(KeyStream);

            try
            {
                // ins.Position = 0; wrong here, ins pos is wrong
                m_N = IntUtils.ReadShort(KeyStream);
                m_Q = IntUtils.ReadShort(KeyStream);
                byte flags = dataStream.ReadByte();
                m_sparse = (flags & 1) != 0;
                m_fastFp = (flags & 2) != 0;

                m_polyType = (flags & 4) == 0 ? 
                    TernaryPolynomialType.SIMPLE : 
                    TernaryPolynomialType.PRODUCT;

                if (PolyType == TernaryPolynomialType.PRODUCT)
                {
                    m_T = ProductFormPolynomial.FromBinary(KeyStream, N);
                }
                else
                {
                    IntegerPolynomial fInt = IntegerPolynomial.FromBinary3Tight(KeyStream, N);

                    if (m_sparse)
                        m_T = new SparseTernaryPolynomial(fInt);
                    else
                        m_T = new DenseTernaryPolynomial(fInt);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("NTRUPrivateKey:Ctor", "The Private key could not be loaded!", ex);
            }

            Initialize();
        }

        /// <summary>
        /// Reads a Private Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public NTRUPrivateKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private NTRUPrivateKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUPrivateKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Private key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized NTRUPrivateKey class</returns>
        public static NTRUPrivateKey From(byte[] KeyArray)
        {
            return new NTRUPrivateKey(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized NTRUPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static NTRUPrivateKey From(MemoryStream KeyStream)
        {
            return new NTRUPrivateKey(KeyStream);
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded NTRUPrivateKey</returns>
        public byte[] ToBytes()
        {
            int flags = (m_sparse ? 1 : 0) + (m_fastFp ? 2 : 0) + (PolyType == TernaryPolynomialType.PRODUCT ? 4 : 0);
            byte[] flagsByte = new byte[] { (byte)flags };
            byte[] tBin;

            if (T.GetType().Equals(typeof(ProductFormPolynomial)))
                tBin = ((ProductFormPolynomial)T).ToBinary();
            else
                tBin = T.ToIntegerPolynomial().ToBinary3Tight();

            return ArrayUtils.Concat(ArrayEncoder.ToByteArray(N), ArrayEncoder.ToByteArray(Q), flagsByte, tBin);
        }

        /// <summary>
        /// Converts the NTRUPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes encoded the NTRUPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded as a byte array</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the encoded NTRUPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded to a byte array</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("NTRUPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded NTRUPrivateKey to an output stream
        /// </summary>
        /// 
        /// <param name="Output">The Output Stream receiving the encoded Private Key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be written</exception>
        public void WriteTo(Stream Output)
        {
            try 
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("NTRUPrivateKey:WriteTo", "The key could not be written!", ex);
            }
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            // Initializes fp from t
            if (m_fastFp)
            {
                m_FP = new IntegerPolynomial(N);
                m_FP.Coeffs[0] = 1;
            }
            else
            {
                m_FP = T.ToIntegerPolynomial().InvertF3();
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
            int hash = 31 * N;
            hash += 31 * (m_fastFp ? 1231 : 1237);
            hash += 31 *  ((FP == null) ? 0 : FP.GetHashCode());
            hash += 31 * (int)PolyType;
            hash += 31 * Q;
            hash += 31 * (m_sparse ? 1231 : 1237);
            hash += 31 * ((T == null) ? 0 : T.GetHashCode());

            return hash;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object obj)
        {
            if (this == obj)
                return true;
            if (obj == null)
                return false;

            NTRUPrivateKey other = (NTRUPrivateKey)obj;
            if (N != other.N)
                return false;
            if (m_fastFp != other.m_fastFp)
                return false;

            if (FP == null)
            {
                if (other.FP != null)
                    return false;
            }
            else if (!FP.Equals(other.FP))
            {
                return false;
            }

            if (PolyType != other.PolyType)
                return false;
            if (Q != other.Q)
                return false;
            if (m_sparse != other.m_sparse)
                return false;

            if (T == null)
            {
                if (other.T != null)
                    return false;
            }
            else if (!T.Equals(other.T))
            {
                return false;
            }

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this NTRUPrivateKey instance
        /// </summary>
        /// 
        /// <returns>NTRUPrivateKey copy</returns>
        public object Clone()
        {
            return new NTRUPrivateKey(m_T, m_FP, m_N, m_Q, m_sparse, m_fastFp, m_polyType);
        }

        /// <summary>
        /// Create a deep copy of this NTRUPrivateKey instance
        /// </summary>
        /// 
        /// <returns>The NTRUPrivateKey copy</returns>
        public object DeepCopy()
        {
            return new NTRUPrivateKey(ToStream());
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
                    m_T.Clear();
                    m_FP.Clear();
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}