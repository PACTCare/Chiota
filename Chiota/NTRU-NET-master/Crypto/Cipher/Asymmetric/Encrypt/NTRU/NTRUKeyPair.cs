#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial;
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

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU
{
    /// <summary>
    /// An Ntru Key-Pair container
    /// </summary>
    public sealed class NTRUKeyPair : IAsymmetricKeyPair
    {
        #region Constants
        private const string ALG_NAME = "NTRUKeyPair";
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private NTRUPrivateKey _privateKey;
        private NTRUPublicKey _publicKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: KeyPair name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Returns the private key
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return _privateKey; }
        }

        /// <summary>
        /// Returns the public key
        /// </summary>
        /// 
        /// <returns>The public key</returns>
        public IAsymmetricKey PublicKey
        {
            get { return _publicKey; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new key pair
        /// </summary>
        /// 
        /// <param name="PublicKey">The Public key</param>
        /// <param name="PrivateKey">The Private Key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public NTRUKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            if (!(PublicKey is NTRUPublicKey))
                throw new CryptoAsymmetricException("NTRUKeyPair:CTor", "Not a valid NTRU Public key!", new InvalidDataException());
            if (!(PrivateKey is NTRUPrivateKey))
                throw new CryptoAsymmetricException("NTRUKeyPair:CTor", "Not a valid NTRU Private key!", new InvalidDataException());

            _publicKey = (NTRUPublicKey)PublicKey;
            _privateKey = (NTRUPrivateKey)PrivateKey;
        }

        /// <summary>
        /// Constructs a new key pair
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid name is used</exception>
        public NTRUKeyPair(IAsymmetricKey Key)
        {
            if (Key is NTRUPublicKey)
                _publicKey = (NTRUPublicKey)Key;
            else if (Key is NTRUPrivateKey)
                _privateKey = (NTRUPrivateKey)Key;
            else
                throw new CryptoAsymmetricException("NTRUKeyPair:CTor", "Not a valid NTRU key!", new InvalidDataException());
        }

        /// <summary>
        /// Reads a key pair from an input stream.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key pair</param>
        public NTRUKeyPair(MemoryStream KeyStream)
        {
            _publicKey = new NTRUPublicKey(KeyStream);
            _privateKey = new NTRUPrivateKey(KeyStream);
        }

        /// <summary>
        /// Reads a key pair  from a byte array.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">An byte array containing an encoded key pair</param>
        public NTRUKeyPair(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private NTRUKeyPair()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUKeyPair()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests if the key pair is valid.
        /// <para>See IEEE 1363.1 section 9.2.4.1.</para>
        /// </summary>
        /// 
        /// <returns>if the key pair is valid, <c>true</c> otherwise false</returns>
        public bool IsValid()
        {
            int N = ((NTRUPrivateKey)PrivateKey).N;
            int q = ((NTRUPrivateKey)PrivateKey).Q;
            TernaryPolynomialType polyType = ((NTRUPrivateKey)PrivateKey).PolyType;

            if (((NTRUPublicKey)PublicKey).N != N)
                return false;
            if (((NTRUPublicKey)PublicKey).Q != q)
                return false;
            if (((NTRUPrivateKey)PrivateKey).T.ToIntegerPolynomial().Coeffs.Length != N)
                return false;

            IntegerPolynomial h = ((NTRUPublicKey)PublicKey).H.ToIntegerPolynomial();
            if (h.Coeffs.Length != N)
                return false;
            if (!h.IsReduced(q))
                return false;

            IntegerPolynomial f = ((NTRUPrivateKey)PrivateKey).T.ToIntegerPolynomial();
            if (polyType == TernaryPolynomialType.SIMPLE && !f.IsTernary())
                return false;
            // if t is a ProductFormPolynomial, ternarity of f1,f2,f3 doesn't need to be verified
            if (polyType == TernaryPolynomialType.PRODUCT && !(((NTRUPrivateKey)PrivateKey).T.GetType().Equals(typeof(ProductFormPolynomial))))
                return false;

            if (polyType == TernaryPolynomialType.PRODUCT)
            {
                f.Multiply(3);
                f.Coeffs[0] += 1;
                f.ModPositive(q);
            }

            // the key generator pre-multiplies h by 3, so divide by 9 instead of 3
            int inv9 = IntEuclidean.Calculate(9, q).X;   // 9^-1 mod q

            IntegerPolynomial g = f.Multiply(h, q);
            g.Multiply(inv9);
            g.ModCenter(q);

            if (!g.IsTernary())
                return false;

            int dg = N / 3;   // see EncryptionParameters.Initialize()
            if (g.Count(1) != dg)
                return false;
            if (g.Count(-1) != dg - 1)
                return false;

            return true;
        }

        /// <summary>
        /// Converts the key pair to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key pair</returns>
        public byte[] ToBytes()
        {
            byte[] pubArr = ((NTRUPublicKey)PublicKey).ToBytes();
            byte[] privArr = ((NTRUPrivateKey)PrivateKey).ToBytes();
            byte[] kpArr = pubArr.CopyOf(pubArr.Length + privArr.Length);
            Array.Copy(privArr, 0, kpArr, pubArr.Length, privArr.Length);

            return kpArr;
        }

        /// <summary>
        /// Returns the current key pair set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>NtruKeyPair as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">NtruKeyPair as a byte array; can be initialized as zero bytes</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">NtruKeyPair as a byte array; can be initialized as zero bytes</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("NTRUKeyPair:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the key pair to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output Stream</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an IO exception is raised</exception>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException ex)
            {
                throw new CryptoAsymmetricException("NTRUKeyPair:WriteTo", ex.Message, ex);
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

            result = prime * result + ((PrivateKey == null) ? 0 : PrivateKey.GetHashCode());
            result = prime * result + ((PublicKey == null) ? 0 : PublicKey.GetHashCode());

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

            NTRUKeyPair other = (NTRUKeyPair)obj;
            if (PrivateKey == null)
            {
                if (other.PrivateKey != null)
                    return false;
            }
            else if (!PrivateKey.Equals(other.PrivateKey))
            {
                return false;
            }
            if (PublicKey == null)
            {
                if (other.PublicKey != null)
                    return false;
            }
            else if (!PublicKey.Equals(other.PublicKey))
            {
                return false;
            }

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this key pair instance
        /// </summary>
        /// 
        /// <returns>The IAsymmetricKeyPair copy</returns>
        public object Clone()
        {
            return new NTRUKeyPair((IAsymmetricKey)_publicKey.Clone(), (IAsymmetricKey)_privateKey.Clone());
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
                    if (_privateKey != null)
                        ((NTRUPrivateKey)_privateKey).Dispose();
                    if (_publicKey != null)
                        ((NTRUPublicKey)_publicKey).Dispose();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}