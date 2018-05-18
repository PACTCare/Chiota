#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
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
// An implementation of the Rainbow Asymmetric Signature Scheme.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle Based on the Bouncy Castle Java 
// <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.
// 
// Implementation Details:
// An implementation of an Rainbow Asymmetric Signature Scheme. 
// Written by John Underhill, July 06, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW
{
    /// <summary>
    /// A Rainbow Public Key
    /// </summary>
    public class RNBWPublicKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "RNBWPublicKey";
        #endregion

        #region Fields
        private short[][] _coeffQuadratic;
        private short[][] _coeffSingular;
        private short[] _coeffScalar;
        private int _docLength;
        private bool m_isDisposed = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the coeff quadratic
        /// </summary>
        internal short[][] CoeffQuadratic
        {
            get { return _coeffQuadratic; }
        }

        /// <summary>
        /// Get: Returns the coeff singular
        /// </summary>
        internal short[][] CoeffSingular
        {
            get { return _coeffSingular; }
        }

        /// <summary>
        /// Get: Returns the coeff scalar
        /// </summary>
        internal short[] CoeffScalar
        {
            get { return _coeffScalar; }
        }

        /// <summary>
        /// Get: Returns the doc length
        /// </summary>
        public int DocLength
        {
            get { return _docLength; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="DocLength">The doc length</param>
        /// <param name="Quadratic">The quadratic coefficient</param>
        /// <param name="Singular">The singular coefficient</param>
        /// <param name="Scalar">The scalar coefficient</param>
        public RNBWPublicKey(int DocLength, short[][] Quadratic, short[][] Singular, short[] Scalar)
        {
            _docLength = DocLength;
            _coeffQuadratic = Quadratic;
            _coeffSingular = Singular;
            _coeffScalar = Scalar;
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public RNBWPublicKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len;
                byte[] data;

                _docLength = reader.ReadInt32();

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffQuadratic = ArrayUtils.ToArray2x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffSingular = ArrayUtils.ToArray2x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffScalar = ArrayUtils.ToArray16(data);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("RNBWPublicKey:CTor", "The RNBWPublicKey could not be loaded!", ex);
            }
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public RNBWPublicKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        private RNBWPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RNBWPublicKey()
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
        /// <returns>An initialized RNBWPublicKey class</returns>
        public static RNBWPublicKey From(byte[] KeyArray)
        {
            return new RNBWPublicKey(KeyArray);
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized RNBWPublicKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static RNBWPublicKey From(Stream KeyStream)
        {
            return new RNBWPublicKey(KeyStream);
        }

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RNBWPublicKey</returns>
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
            byte[] data;

            writer.Write(_docLength);

            data = ArrayUtils.ToBytes(_coeffQuadratic);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_coeffSingular);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_coeffScalar);
            writer.Write(data.Length);
            writer.Write(data);

            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the RNBWPublicKey to an output byte array
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
        /// Writes the encoded RNBWPublicKey to an output byte array
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
                throw new CryptoAsymmetricException("RNBWPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded RNBWPublicKey to an output stream
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
                throw new CryptoAsymmetricException("RNBWPublicKey:WriteTo", "The Public key could not be written!", ex);
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
            if (Obj == null || !(Obj is RNBWPublicKey))
                return false;

            RNBWPublicKey other = (RNBWPublicKey)Obj;

            if (!_docLength.Equals(other.DocLength))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_coeffQuadratic), ArrayUtils.ToBytes(other.CoeffQuadratic)))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_coeffSingular), ArrayUtils.ToBytes(other.CoeffSingular)))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_coeffScalar), ArrayUtils.ToBytes(other.CoeffScalar)))
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
            int hash = _docLength * 31;
            hash += ArrayUtils.GetHashCode(_coeffQuadratic);
            hash += ArrayUtils.GetHashCode(_coeffSingular);
            hash += ArrayUtils.GetHashCode(_coeffScalar);

            return hash;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this RNBWPublicKey instance
        /// </summary>
        /// 
        /// <returns>RNBWPublicKey copy</returns>
        public object Clone()
        {
            return new RNBWPublicKey(_docLength, _coeffQuadratic, _coeffSingular, _coeffScalar);
        }

        /// <summary>
        /// Create a deep copy of this RNBWPublicKey instance
        /// </summary>
        /// 
        /// <returns>The RNBWPublicKey copy</returns>
        public object DeepCopy()
        {
            return new RNBWPublicKey(ToStream());
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
                    if (_coeffQuadratic != null)
                    {
                        Array.Clear(_coeffQuadratic, 0, _coeffQuadratic.Length);
                        _coeffQuadratic = null;
                    }
                    if (_coeffSingular != null)
                    {
                        Array.Clear(_coeffSingular, 0, _coeffSingular.Length);
                        _coeffSingular = null;
                    }
                    if (_coeffScalar != null)
                    {
                        Array.Clear(_coeffScalar, 0, _coeffScalar.Length);
                        _coeffScalar = null;
                    }
                    _docLength = 0;
                    
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
