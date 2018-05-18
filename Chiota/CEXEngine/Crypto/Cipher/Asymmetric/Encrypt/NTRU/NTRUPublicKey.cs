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
    /// An NTRU Public Key
    /// </summary>
    public sealed class NTRUPublicKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "NTRUPublicKey";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private int m_N;
        private int m_Q;
        private IntegerPolynomial m_H;
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
        /// The number of coefficients in the polynomial <c>H</c>
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// The big Q modulus
        /// </summary>
        public int Q
        {
            get { return m_Q; }
        }

        /// <summary>
        /// The polynomial <c>H</c> which determines the key
        /// </summary>
        internal IntegerPolynomial H
        {
            get { return m_H; }
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
            m_H = H;
            m_N = N;
            m_Q = Q;
        }

        /// <summary>
        /// Read a Public Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public NTRUPublicKey(Stream KeyStream)
        {
            try
            {
                m_N = IntUtils.ReadShort(KeyStream);
                m_Q = IntUtils.ReadShort(KeyStream);
                m_H = IntegerPolynomial.FromBinary(KeyStream, N, Q);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("NTRUPublicKey:CTor", "The Public key could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Read a Public Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public NTRUPublicKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
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
        /// Read a Public key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized NTRUPublicKey class</returns>
        public static NTRUPublicKey From(byte[] KeyArray)
        {
            return new NTRUPublicKey(KeyArray);
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized NTRUPublicKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static NTRUPublicKey From(MemoryStream KeyStream)
        {
            return new NTRUPublicKey(KeyStream);
        }

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded NTRUPublicKey</returns>
        public byte[] ToBytes()
        {
            return ArrayUtils.Concat(ArrayEncoder.ToByteArray(N), ArrayEncoder.ToByteArray(Q), H.ToBinary(Q));
        }

        /// <summary>
        /// Converts the Public key to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Public Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the encoded NTRUPublicKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Public Key encoded as a byte array</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the encoded NTRUPublicKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Public Key encoded to a byte array</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("NTRUPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded NTRUPublicKey to an output stream
        /// </summary>
        /// 
        /// <param name="Output">The Output Stream receiving the encoded Public Key</param>
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
                throw new CryptoAsymmetricException("NTRUPublicKey:WriteTo", "The Public key could not be written!", ex);
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
            hash += ((H == null) ? 0 : H.GetHashCode());
            hash += 31 * Q;

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
        /// Create a shallow copy of this NTRUPublicKey instance
        /// </summary>
        /// 
        /// <returns>NTRUPublicKey copy</returns>
        public object Clone()
        {
            return new NTRUPublicKey(m_H, m_N, m_Q);
        }

        /// <summary>
        /// Create a deep copy of this NTRUPublicKey instance
        /// </summary>
        /// 
        /// <returns>The NTRUPublicKey copy</returns>
        public object DeepCopy()
        {
            return new NTRUPublicKey(ToStream());
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

                    if (m_H != null)
                        m_H.Clear();
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}