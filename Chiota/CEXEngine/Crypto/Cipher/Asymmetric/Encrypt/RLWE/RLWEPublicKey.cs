#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// The Ring-LWE Asymmetric Cipher
// 
// Implementation Details:
// An implementation based on the description in the paper 'Efficient Software Implementation of Ring-LWE Encryption' 
// https://eprint.iacr.org/2014/725.pdf and accompanying Github project: https://github.com/ruandc/Ring-LWE-Encryption
// Written by John Underhill, June 8, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE
{
    /// <summary>
    /// A Ring-LWE Public Key
    /// </summary>
    public class RLWEPublicKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "RLWEPublicKey";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        // the length of the code
        private byte[] m_A;
        // the error correction capability of the code
        private byte[] m_P;
        // the number of coefficients
        private int m_N;
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
        /// Get: Returns the A array
        /// </summary>
        internal byte[] A
        {
            get { return m_A; }
        }

        /// <summary>
        /// Get: Returns the number of coefficients
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// Get: Returns the P array
        /// </summary>
        internal byte[] P
        {
            get { return m_P; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        /// <param name="A">The polynomial 'a'</param>
        /// <param name="P">The polynomial 'p'</param>
        public RLWEPublicKey(int N, byte[] A, byte[] P)
        {
            m_N = N;
            m_A = A;
            m_P = P;
        }
        
        /// <summary>
        /// Read a Public Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public RLWEPublicKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len = 0;
                // num coeffs
                m_N = reader.ReadInt32();
                // a poly
                len = reader.ReadInt32();
                m_A = reader.ReadBytes(len);
                // p poly
                len = reader.ReadInt32();
                m_P = reader.ReadBytes(len);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("RLWEPublicKey:CTor", "The Public key could not be loaded!", ex);
            }
        }
        
        /// <summary>
        /// Read a Public Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public RLWEPublicKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private RLWEPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEPublicKey()
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
        /// <returns>An initialized RLWEPublicKey class</returns>
        public static RLWEPublicKey From(byte[] KeyArray)
        {
            return new RLWEPublicKey(KeyArray);
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized RLWEPublicKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static RLWEPublicKey From(Stream KeyStream)
        {
            return new RLWEPublicKey(KeyStream);
        }

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RLWEPublicKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the Public key to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Public Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            // num coeff
            writer.Write(N);
            // write 'a' poly
            writer.Write(m_A.Length);
            writer.Write(m_A);
            // write 'p' poly
            writer.Write(m_P.Length);
            writer.Write(m_P);
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the RLWEPublicKey to an output byte array
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
        /// Writes the encoded RLWEPublicKey to an output byte array
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
                throw new CryptoAsymmetricException("RLWEPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded RLWEPublicKey to an output stream
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
                throw new CryptoAsymmetricException("RLWEPublicKey:WriteTo", "The Public key could not be written!", ex);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is RLWEPublicKey))
                return false;

            RLWEPublicKey key = (RLWEPublicKey)Obj;

            if (!N.Equals(key.N))
                return false;

            for (int i = 0; i < A.Length; i++)
            {
                if (key.A[i] != A[i])
                    return false;
            }
            for (int i = 0; i < P.Length; i++)
            {
                if (key.P[i] != P[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = N * 31;
            hash += ArrayUtils.GetHashCode(A);
            hash += ArrayUtils.GetHashCode(P);

            return hash;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this RLWEPublicKey instance
        /// </summary>
        /// 
        /// <returns>RLWEPublicKey copy</returns>
        public object Clone()
        {
            return new RLWEPublicKey(m_N, m_A, m_P);
        }

        /// <summary>
        /// Create a deep copy of this RLWEPublicKey instance
        /// </summary>
        /// 
        /// <returns>The RLWEPublicKey copy</returns>
        public object DeepCopy()
        {
            return new RLWEPrivateKey(ToStream());
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
                    if (m_A != null)
                    {
                        Array.Clear(m_A, 0, m_A.Length);
                        m_A = null;
                    }
                    if (m_P != null)
                    {
                        Array.Clear(m_P, 0, m_P.Length);
                        m_P = null;
                    }
                    m_N = 0;
                    
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
