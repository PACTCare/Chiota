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
    /// A NtruEncrypt public key is essentially a polynomial named <c>h</c>.
    /// </summary>
    public sealed class NTRUPublicKey : IAsymmetricKey
    {
        #region Fields
        private bool _isDisposed = false;
        private int _N;
        private int _Q;
        private IntegerPolynomial _H;
        #endregion

        #region Properties
        /// <summary>
        /// The number of coefficients in the polynomial <c>H</c>
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// The big Q modulus
        /// </summary>
        public int Q
        {
            get { return _Q; }
        }

        /// <summary>
        /// The polynomial <c>H</c> which determines the key
        /// </summary>
        internal IntegerPolynomial H
        {
            get { return _H; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new public key from a polynomial
        /// </summary>
        /// 
        /// <param name="H">The polynomial <c>H</c> which determines the key</param>
        /// <param name="N">The number of coefficients in the polynomial <c>H</c></param>
        /// <param name="Q">The "big" NtruEncrypt modulus</param>
        internal NTRUPublicKey(IntegerPolynomial H, int N, int Q)
        {
            _H = H;
            _N = N;
            _Q = Q;
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="NTRUException">Thrown if the key could not be loaded</exception>
        public NTRUPublicKey(Stream KeyStream)
        {
            try
            {
                _N = IntUtils.ReadShort(KeyStream);
                _Q = IntUtils.ReadShort(KeyStream);
                _H = IntegerPolynomial.FromBinary(KeyStream, N, Q);
            }
            catch (IOException ex)
            {
                throw new NTRUException("NTRUPublicKey:CTor", "The Public key could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public NTRUPublicKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        private NTRUPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NTRUPublicKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Read a Public key from a byte array.
        /// <para>The array can contain only the public key.</para>
        /// </summary>
        /// 
        /// <param name="Key">The byte array containing the key</param>
        /// 
        /// <returns>An initialized NTRUPublicKey class</returns>
        public static NTRUPublicKey From(byte[] Key)
        {
            return From(new MemoryStream(Key));
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the key</param>
        /// 
        /// <returns>An initialized NTRUPublicKey class</returns>
        /// 
        /// <exception cref="NTRUException">Thrown if the stream can not be read</exception>
        public static NTRUPublicKey From(MemoryStream KeyStream)
        {
            try
            {
                int n = IntUtils.ReadShort(KeyStream);
                int q = IntUtils.ReadShort(KeyStream);
                IntegerPolynomial h = IntegerPolynomial.FromBinary(KeyStream, n, q);

                return new NTRUPublicKey(h, n, q);
            }
            catch (IOException ex)
            {
                throw new NTRUException("NTRUPublicKey:From", ex.Message, ex);
            }
        }

        /// <summary>
        /// Converts the key to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key</returns>
        public byte[] ToBytes()
        {
            return ArrayUtils.Concat(ArrayEncoder.ToByteArray(N), ArrayEncoder.ToByteArray(Q), H.ToBinary(Q));
        }

        /// <summary>
        /// Returns the current public key as a MemoryStream
        /// </summary>
        /// 
        /// <returns>NtruPublicKey as a MemoryStream</returns>
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
                throw new NTRUException("NTRUPublicKey:WriteTo", "The Public key could not be written!", ex);
            }
        }

        /// <summary>
        /// Writes the public key to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">NtruPublicKey as a byte array; can be initialized as zero bytes</param>
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
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="NTRUException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new NTRUException("NTRUPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
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
            result = prime * result + ((H == null) ? 0 : H.GetHashCode());
            result = prime * result + Q;

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

            NTRUPublicKey other = (NTRUPublicKey)Obj;
            if (N != other.N)
                return false;

            if (H == null)
            {
                if (other.H != null)
                    return false;
            }
            else if (!H.Equals(other.H))
            {
                return false;
            }

            if (Q != other.Q)
                return false;

            return true;
        }
        #endregion


        #region IClone
        /// <summary>
        /// Create a copy of this NTRUPublicKey instance
        /// </summary>
        /// 
        /// <returns>NTRUPublicKey copy</returns>
        public object Clone()
        {
            return new NTRUPublicKey(_H, _N, _Q);
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

                    if (_H != null)
                        _H.Clear();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}