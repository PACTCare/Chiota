#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.CryptoException;
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
    /// A Ring-LWE Private Key
    /// </summary>
    public class RLWEPrivateKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "RLWEPrivateKey";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private byte[] m_R2;
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
        /// Get: Returns the private key as a byte array
        /// </summary>
        internal byte[] R2
        {
            get { return m_R2; }
        }

        /// <summary>
        /// Get: Returns the number of coefficients
        /// </summary>
        public int N
        {
            get { return m_N; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        /// <param name="R2">The private key as a byte array</param>
        public RLWEPrivateKey(int N, byte[] R2)
        {
            m_N = N;
            m_R2 = R2;
        }

        /// <summary>
        /// Reads a Private Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public RLWEPrivateKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                // num coef
                m_N = reader.ReadInt32();
                // key len
                int klen = reader.ReadInt32();
                m_R2 = reader.ReadBytes(klen);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("RLWEPrivateKey:CTor", "The Private key could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reads a Private Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public RLWEPrivateKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private RLWEPrivateKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEPrivateKey()
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
        /// <returns>An initialized RLWEPrivateKey class</returns>
        public static RLWEPrivateKey From(byte[] KeyArray)
        {
            return new RLWEPrivateKey(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized RLWEPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static RLWEPrivateKey From(Stream KeyStream)
        {
            return new RLWEPrivateKey(KeyStream);
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RLWEPrivateKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the RLWEPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());

            // num coeff
            writer.Write(N);
            // length
            writer.Write(m_R2.Length);
            // write key
            writer.Write(m_R2);
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the RLWEPrivateKey to an output byte array
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
        /// Writes the encoded RLWEPrivateKey to an output byte array
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
                throw new CryptoAsymmetricException("RLWEPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded RLWEPrivateKey to an output stream
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
                throw new CryptoAsymmetricException("RLWEPrivateKey:WriteTo", "The key could not be written!", ex);
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
            if (Obj == null || !(Obj is RLWEPrivateKey))
                return false;

            RLWEPrivateKey key = (RLWEPrivateKey)Obj;

            if (!N.Equals(key.N))
                return false;

            for (int i = 0; i < R2.Length; i++)
            {
                if (key.R2[i] != R2[i])
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
            hash += Utility.ArrayUtils.GetHashCode(R2);

            return hash;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>MPKCPublicKey copy</returns>
        public object Clone()
        {
            return new RLWEPrivateKey(m_N, m_R2);
        }

        /// <summary>
        /// Create a deep copy of this RLWEPrivateKey instance
        /// </summary>
        /// 
        /// <returns>The RLWEPrivateKey copy</returns>
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
                    if (m_R2 != null)
                    {
                        Array.Clear(m_R2, 0, m_R2.Length);
                        m_R2 = null;
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
