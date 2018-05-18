#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
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
// An implementation of the Generalized Merkle Signature Scheme Asymmetric Signature Scheme.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle Based on the Bouncy Castle Java 
// <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.
// 
// Implementation Details:
// An implementation of an Generalized Merkle Signature Scheme. 
// Written by John Underhill, July 06, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS
{
    /// <summary>
    /// A Generalized Merkle Signature Scheme Public Key
    /// </summary>
    public sealed class GMSSPublicKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "GMSSPublicKey";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private byte[] m_publicKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the doc length
        /// </summary>
        public byte[] PublicKey
        {
            get { return m_publicKey; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the public key</param>
        public GMSSPublicKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public GMSSPublicKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len = reader.ReadInt32();
                m_publicKey = reader.ReadBytes(len);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("GMSSPublicKey:CTor", "The GMSSPublicKey could not be loaded!", ex);
            }
        }

        private GMSSPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSPublicKey()
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
        /// <returns>An initialized GMSSPublicKey class</returns>
        public static GMSSPublicKey From(byte[] KeyArray)
        {
            return new GMSSPublicKey(KeyArray);
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized GMSSPublicKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static GMSSPublicKey From(Stream KeyStream)
        {
            return new GMSSPublicKey(KeyStream);
        }

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded GMSSPublicKey</returns>
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

            writer.Write(m_publicKey.Length);
            writer.Write(m_publicKey);
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the GMSSPublicKey to an output byte array
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
        /// Writes the encoded GMSSPublicKey to an output byte array
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
                throw new CryptoAsymmetricException("GMSSPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded GMSSPublicKey to an output stream
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
            catch (IOException ex)
            {
                throw new CryptoAsymmetricException("GMSSPublicKey:WriteTo", "The Public key could not be written!", ex);
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
            if (Obj == null || !(Obj is GMSSPublicKey))
                return false;

            GMSSPublicKey other = (GMSSPublicKey)Obj;

            if (!Compare.IsEqual(m_publicKey, other.PublicKey))
                return false;

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return CEXEngine.Utility.ArrayUtils.GetHashCode(m_publicKey);
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this GMSSPublicKey instance
        /// </summary>
        /// 
        /// <returns>GMSSPublicKey copy</returns>
        public object Clone()
        {
            return new GMSSPublicKey(m_publicKey);
        }

        /// <summary>
        /// Create a deep copy of this GMSSPublicKey instance
        /// </summary>
        /// 
        /// <returns>The GMSSPublicKey copy</returns>
        public object DeepCopy()
        {
            return new GMSSPublicKey(ToStream());
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
                    if (m_publicKey != null)
                    {
                        Array.Clear(m_publicKey, 0, m_publicKey.Length);
                        m_publicKey = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
