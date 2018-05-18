#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.Arithmetic;
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
    /// A Rainbow Private Key
    /// </summary>
    public class RNBWPrivateKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "RNBWPrivateKey";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        // the inverse of A1, (n-v1 x n-v1 matrix)
        private short[][] _a1Inv;
        // translation vector of L1
        private short[] _B1;
        // the inverse of A2, (n x n matrix)
        private short[][] _a2Inv;
        // translation vector of L2
        private short[] _B2;
        // the number of Vinegar-variables per layer.
        private int[] _VI;
        // contains the polynomials with their coefficients of private map F
        private MapLayer[] _layers;
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
        internal short[] B1
        {
            get { return _B1; }
        }

        /// <summary>
        /// Get: Returns the inverse matrix of A1
        /// </summary>
        internal short[][] InvA1
        {
            get { return _a1Inv; }
        }

        /// <summary>
        /// Get: Returns the translation part of the private quadratic map L2
        /// </summary>
        internal short[] B2
        {
            get { return _B2; }
        }

        /// <summary>
        /// Get: Returns the inverse matrix of A2
        /// </summary>
        internal short[][] InvA2
        {
            get { return _a2Inv; }
        }

        /// <summary>
        /// Get: Returns the layers contained in the private key
        /// </summary>
        public MapLayer[] Layers
        {
            get { return _layers; }
        }

        /// <summary>
        /// Get: Returns the array of vi-s
        /// </summary>
        public int[] VI
        {
            get { return _VI; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="A1inv">The inverse of A1(the matrix part of the affine linear map L1) (n-v1 x n-v1 matrix)</param>
        /// <param name="B1">Translation vector, part of the linear affine map L1</param>
        /// <param name="A2inv">The inverse of A2(the matrix part of the affine linear map L2) (n x n matrix)</param>
        /// <param name="B2">Translation vector, part of the linear affine map L2</param>
        /// <param name="Vi">The number of Vinegar-variables per layer</param>
        /// <param name="Layers">The polynomials with their coefficients of private map F</param>
        internal RNBWPrivateKey(short[][] A1inv, short[] B1, short[][] A2inv, short[] B2, int[] Vi, MapLayer[] Layers)
        { 
            _a1Inv = A1inv;
            _B1 = B1;
            _a2Inv = A2inv;
            _B2 = B2;
            _VI = Vi;
            _layers = Layers;
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if the key could not be loaded</exception>
        public RNBWPrivateKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len;
                byte[] data;

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _a1Inv = ArrayUtils.ToArray2x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _B1 = ArrayUtils.ToArray16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _a2Inv = ArrayUtils.ToArray2x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _B2 = ArrayUtils.ToArray16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _VI = ArrayUtils.ToArray32(data);

                len = reader.ReadInt32();
                _layers = new MapLayer[len];

                for (int i = 0; i < _layers.Length; i++)
                {
                    len = reader.ReadInt32();
                    data = reader.ReadBytes(len);
                    _layers[i] = new MapLayer(data);
                }

            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("RNBWPrivateKey:CTor", "The RNBWPrivateKey could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public RNBWPrivateKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        private RNBWPrivateKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RNBWPrivateKey()
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
        /// <returns>An initialized RNBWPrivateKey class</returns>
        public static RNBWPrivateKey From(byte[] KeyArray)
        {
            return new RNBWPrivateKey(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized RNBWPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static RNBWPrivateKey From(Stream KeyStream)
        {
            return new RNBWPrivateKey(KeyStream);
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RNBWPrivateKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the RNBWPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] data;

            data = ArrayUtils.ToBytes(_a1Inv);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_B1);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_a2Inv);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_B2);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_VI);
            writer.Write(data.Length);
            writer.Write(data);

            writer.Write(_layers.Length);
            for (int i = 0; i < _layers.Length; i++)
            {
                data = _layers[i].ToBytes();
                writer.Write(data.Length);
                writer.Write(data);
            }

            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the RNBWPrivateKey to an output byte array
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
        /// Writes the encoded RNBWPrivateKey to an output byte array
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
                throw new CryptoAsymmetricException("RNBWPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded RNBWPrivateKey to an output stream
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
            catch (IOException ex)
            {
                throw new CryptoAsymmetricException("RNBWPrivateKey:WriteTo", "The key could not be written!", ex);
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
            if (Obj == null || !(Obj is RNBWPrivateKey))
                return false;

            RNBWPrivateKey other = (RNBWPrivateKey)Obj;

            if (!Compare.IsEqual(ArrayUtils.ToBytes(_a1Inv), ArrayUtils.ToBytes(other.InvA1)))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_B1), ArrayUtils.ToBytes(other.B1)))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_a2Inv), ArrayUtils.ToBytes(other.InvA2)))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_B2), ArrayUtils.ToBytes(other.B2)))
                return false;
            if (!Compare.IsEqual(ArrayUtils.ToBytes(_VI), ArrayUtils.ToBytes(other.VI)))
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
            int hash = ArrayUtils.GetHashCode(_a1Inv);
            hash += ArrayUtils.GetHashCode(_B1);
            hash += ArrayUtils.GetHashCode(_a2Inv);
            hash += ArrayUtils.GetHashCode(_B2);
            hash += ArrayUtils.GetHashCode(_VI);

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
            return new RNBWPrivateKey(_a1Inv, _B1, _a2Inv, _B2, _VI, _layers);
        }

        /// <summary>
        /// Create a deep copy of this RNBWPrivateKey instance
        /// </summary>
        /// 
        /// <returns>The RNBWPrivateKey copy</returns>
        public object DeepCopy()
        {
            return new RNBWPrivateKey(ToStream());
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
                    if (_a1Inv != null)
                    {
                        Array.Clear(_a1Inv, 0, _a1Inv.Length);
                        _a1Inv = null;
                    }
                    if (_B1 != null)
                    {
                        Array.Clear(_B1, 0, _B1.Length);
                        _B1 = null;
                    }
                    if (_a2Inv != null)
                    {
                        Array.Clear(_a2Inv, 0, _a2Inv.Length);
                        _a2Inv = null;
                    }
                    if (_B2 != null)
                    {
                        Array.Clear(_B2, 0, _B2.Length);
                        _B2 = null;
                    }
                    if (_VI != null)
                    {
                        Array.Clear(_VI, 0, _VI.Length);
                        _VI = null;
                    }
                    if (_layers != null)
                    {
                        for (int i = 0; i < _layers.Length; i++)
                        {
                            _layers[i].Dispose();
                            _layers[i] = null;
                        }
                        _layers = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
