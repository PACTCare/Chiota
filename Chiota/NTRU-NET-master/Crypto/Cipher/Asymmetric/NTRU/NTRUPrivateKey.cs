#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Exceptions;
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

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU
{
    /// <summary>
    /// A NtruEncrypt private key is essentially a polynomial named <c>f</c>
    /// which takes different forms depending on whether product-form polynomials are used. 
    /// <para>On <c>FastP</c> the inverse of <c>f</c> modulo <c>p</c> is precomputed on initialization.</para>
    /// </summary>
    public sealed class NTRUPrivateKey : IAsymmetricKey
    {
        #region Fields
        private bool _fastFp;
        private bool _isDisposed = false;
        private TernaryPolynomialType _polyType;
        private bool _sparse;
        private IntegerPolynomial _FP;
        private int _N;
        private int _Q;
        private IPolynomial _T;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The number of polynomial coefficients
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Get: The big Q modulus
        /// </summary>
        public int Q
        {
            get { return _Q; }
        }

        /// <summary>
        /// Get: PolyType type of the polynomial <c>T</c>
        /// </summary>
        internal TernaryPolynomialType PolyType
        {
            get { return _polyType; }
        }

        /// <summary>
        /// Get/Set: The polynomial which determines the key: if <c>FastFp=true</c>, <c>F=1+3T</c>; otherwise, <c>F=T</c>
        /// <para>Set can be readonly in distribution</para>
        /// </summary>
        internal IPolynomial T
        {
            get { return _T; }
            set { _T = value; }
        }

        /// <summary>
        /// Get: Fp the inverse of <c>F</c>
        /// </summary>
        internal IntegerPolynomial FP
        {
            get { return _FP; }
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
            _T = T;
            _FP = FP;
            _N = N;
            _Q = Q;
            _sparse = Sparse;
            _fastFp = FastFp;
            _polyType = PolyType;
        }

        /// <summary>
        /// Converts a byte array to a polynomial <c>f</c> and constructs a new private key
        /// </summary>
        /// 
        /// <param name="Data">An encoded polynomial</param>
        public NTRUPrivateKey(byte[] Data) :
            this(new MemoryStream(Data))
        {
        }

        /// <summary>
        /// Reads a polynomial <c>f</c> from an input stream and constructs a new private key
        /// </summary>
        /// 
        /// <param name="InputStream">An input stream</param>
        /// 
        /// <exception cref="NTRUException">Thrown if the key could not be loaded</exception>
        public NTRUPrivateKey(MemoryStream InputStream)
        {
            BinaryReader dataStream = new BinaryReader(InputStream);

            try
            {
                // ins.Position = 0; wrong here, ins pos is wrong
                _N = IntUtils.ReadShort(InputStream);
                _Q = IntUtils.ReadShort(InputStream);
                byte flags = dataStream.ReadByte();
                _sparse = (flags & 1) != 0;
                _fastFp = (flags & 2) != 0;

                _polyType = (flags & 4) == 0 ? 
                    TernaryPolynomialType.SIMPLE : 
                    TernaryPolynomialType.PRODUCT;

                if (PolyType == TernaryPolynomialType.PRODUCT)
                {
                    _T = ProductFormPolynomial.FromBinary(InputStream, N);
                }
                else
                {
                    IntegerPolynomial fInt = IntegerPolynomial.FromBinary3Tight(InputStream, N);

                    if (_sparse)
                        _T = new SparseTernaryPolynomial(fInt);
                    else
                        _T = new DenseTernaryPolynomial(fInt);
                }
            }
            catch (IOException ex)
            {
                throw new NTRUException("NTRUPrivateKey:Ctor", "The Private key could not be loaded!", ex);
            }

            Initialize();
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
        /// Read a Private key from a byte array.
        /// <para>The array can contain only the public key.</para>
        /// </summary>
        /// 
        /// <param name="Key">The byte array containing the key</param>
        /// 
        /// <returns>An initialized NTRUPrivateKey class</returns>
        public static NTRUPrivateKey From(byte[] Key)
        {
            return From(new MemoryStream(Key));
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the key</param>
        /// 
        /// <returns>An initialized NTRUPrivateKey class</returns>
        /// 
        /// <exception cref="NTRUException">Thrown if the stream can not be read</exception>
        public static NTRUPrivateKey From(MemoryStream KeyStream)
        {
            BinaryReader dataStream = new BinaryReader(KeyStream);

            try
            {
                // ins.Position = 0; wrong here, ins pos is wrong
                int n = IntUtils.ReadShort(KeyStream);
                int q = IntUtils.ReadShort(KeyStream);
                byte flags = dataStream.ReadByte();
                bool sparse = (flags & 1) != 0;
                bool fastFp = (flags & 2) != 0;
                IPolynomial t;

                TernaryPolynomialType polyType = (flags & 4) == 0 ?
                    TernaryPolynomialType.SIMPLE :
                    TernaryPolynomialType.PRODUCT;

                if (polyType == TernaryPolynomialType.PRODUCT)
                {
                    t = ProductFormPolynomial.FromBinary(KeyStream, n);
                }
                else
                {
                    IntegerPolynomial fInt = IntegerPolynomial.FromBinary3Tight(KeyStream, n);

                    if (sparse)
                        t = new SparseTernaryPolynomial(fInt);
                    else
                        t = new DenseTernaryPolynomial(fInt);
                }

                // Initializes fp from t
                IntegerPolynomial fp;
                if (fastFp)
                {
                    fp = new IntegerPolynomial(n);
                    fp.Coeffs[0] = 1;
                }
                else
                {
                    fp = t.ToIntegerPolynomial().InvertF3();
                }

                return new NTRUPrivateKey(t, fp, n, q, sparse, fastFp, polyType);
            }
            catch (IOException ex)
            {
                throw new NTRUException("NTRUPrivateKey:From", ex.Message, ex);
            }
        }

        /// <summary>
        /// Converts the key to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key</returns>
        public byte[] ToBytes()
        {
            int flags = (_sparse ? 1 : 0) + (_fastFp ? 2 : 0) + (PolyType == TernaryPolynomialType.PRODUCT ? 4 : 0);
            byte[] flagsByte = new byte[] { (byte)flags };
            byte[] tBin;

            if (T.GetType().Equals(typeof(ProductFormPolynomial)))
                tBin = ((ProductFormPolynomial)T).ToBinary();
            else
                tBin = T.ToIntegerPolynomial().ToBinary3Tight();

            return ArrayUtils.Concat(ArrayEncoder.ToByteArray(N), ArrayEncoder.ToByteArray(Q), flagsByte, tBin);
        }

        /// <summary>
        /// Returns the current private key as a MemoryStream
        /// </summary>
        /// 
        /// <returns>NtruPrivateKey as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the key to an output stream
        /// </summary>
        /// 
        /// <param name="Output">An output stream</param>
        /// 
        /// <exception cref="NTRUException">Thrown if the key could not be written</exception>
        public void WriteTo(Stream Output)
        {
            try 
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException ex)
            {
                throw new NTRUException("NTRUPrivateKey:WriteTo", "The key could not be written!", ex);
            }
        }

        /// <summary>
        /// Writes the private key to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">NtruPrivateKey as a byte array; can be initialized as zero bytes</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the private key to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">NtruPrivateKey as a byte array; array must be initialized and of sufficient length</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="NTRUException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new NTRUException("NTRUPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            // Initializes fp from t
            if (_fastFp)
            {
                _FP = new IntegerPolynomial(N);
                _FP.Coeffs[0] = 1;
            }
            else
            {
                _FP = T.ToIntegerPolynomial().InvertF3();
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
            int prime = 31;
            int result = 1;

            result = prime * result + N;
            result = prime * result + (_fastFp ? 1231 : 1237);
            result = prime * result + ((FP == null) ? 0 : FP.GetHashCode());
            result = prime * result + PolyType.GetHashCode();
            result = prime * result + Q;
            result = prime * result + (_sparse ? 1231 : 1237);
            result = prime * result + ((T == null) ? 0 : T.GetHashCode());

            return result;
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
            if (_fastFp != other._fastFp)
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
            if (_sparse != other._sparse)
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
        /// Create a copy of this NTRUPrivateKey instance
        /// </summary>
        /// 
        /// <returns>NTRUPrivateKey copy</returns>
        public object Clone()
        {
            return new NTRUPrivateKey(_T, _FP, _N, _Q, _sparse, _fastFp, _polyType);
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
                    _T.Clear();
                    _FP.Clear();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}