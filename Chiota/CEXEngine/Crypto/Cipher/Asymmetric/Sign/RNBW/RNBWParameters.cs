#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
    /// Creates, reads and writes parameter settings for Rainbow.
    /// <para>Predefined parameter sets are available through the <see cref="RNBWParamSets"/> class.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (RNBWParameters mp = new RNBWParameters(new byte[] { 4, 1, 2, 1 }, new int[] { 19, 26, 32, 38, 49 }))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWSign"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>Rainbow Parameter Description:</description>
    /// <list type="table">
    /// <item><description>OId - Three bytes that uniquely identify the parameter set.</description></item>
    /// <item><description>Vi - An array containing the number of vinegar variables per layer.</description></item>
    /// <item><description>Engine - The Prng engine.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Selecting Parameters for the <a href="http://eprint.iacr.org/2010/437.pdf">Rainbow Signature Scheme</a></description></item>
    /// </list>
    /// </remarks>
    public sealed class RNBWParameters : IAsymmetricParameters
    {
        #region Constants
        private const int OID_SIZE = 4;
        private static readonly int[] DEFAULT_VI = { 6, 12, 17, 22, 33 };
        private const string ALG_NAME = "RNBWParameters";
        #endregion

        #region Fields
        private int[] _VI;
        private byte[] m_oId = new byte[3];
        private bool m_isDisposed = false;
        private Prngs m_rndEngine = Prngs.CTRPrng;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Parameters name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Four bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return m_oId; }
            private set { m_oId = value; }
        }

        /// <summary>
        /// Get: The number of vinegar vars per layer
        /// </summary>
        public int[] Vi
        {
            get { return _VI; }
        }

        /// <summary>
        /// Get: The number of layers
        /// </summary>
        public int NumLayers
        {
           get { return _VI.Length - 1; }
        }

        /// <summary>
        /// Get: The number of all the polynomials in Rainbow
        /// </summary>
        public int DocLength
        {
            get { return _VI[_VI.Length - 1] - _VI[0]; }
        }

        /// <summary>
        /// The random engine used by SecureRandom
        /// </summary>
        public Prngs RandomEngine
        {
            get { return m_rndEngine; }
            private set {m_rndEngine = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// 
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The Rainbow family must be <c>4</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="Vi">An array containing the number of vinegar variables per layer</param>
        /// <param name="Engine">The PRNG engine used to power SecureRandom</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if the Vi or Oid settings are invalid</exception>
        public RNBWParameters(byte[] OId, int[] Vi, Prngs Engine = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("RNBWParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.Rainbow)
                throw new CryptoAsymmetricException("RNBWParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.Rainbow, new ArgumentException()));

            m_oId = OId;
            _VI = Vi;
            m_rndEngine = Engine;

            if (!CheckParams())
                throw new CryptoAsymmetricException("RNBWParameters:CTor", "The RNBWParameters Vi setting is invalid!", new ArgumentException());
        }
                
        /// <summary>
        /// Reconstructs a RNBWParameters from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="ParamStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public RNBWParameters(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                int len;
                byte[] data;

                m_rndEngine = (Prngs)reader.ReadInt32();
                m_oId = reader.ReadBytes(OID_SIZE);
                len = reader.ReadInt32();
                _VI = new int[len];
                data = reader.ReadBytes(len * 4);
                _VI = ArrayUtils.ToArray32(data);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("RNBWParameters:CTor", "The RNBWParameters could not be loaded!", ex);
            }
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="ParamArray">The encoded key array</param>
        public RNBWParameters(byte[] ParamArray) :
            this(new MemoryStream(ParamArray))
        {
        }

        private RNBWParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RNBWParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read an encoded Parameter set from a byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">The byte array containing the parameters</param>
        /// 
        /// <returns>An initialized RNBWParameters class</returns>
        public static RNBWParameters From(byte[] ParamArray)
        {
            return new RNBWParameters(ParamArray);
        }

        /// <summary>
        /// Read an encoded Parameters set from a Stream
        /// </summary>
        /// 
        /// <param name="ParamStream">The Stream containing the encoded Parameter set</param>
        /// 
        /// <returns>An initialized RNBWParameters class</returns>
        public static RNBWParameters From(Stream ParamStream)
        {
            return new RNBWParameters(ParamStream);
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded byte array
        /// </summary>
        /// 
        /// <returns>RNBWParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded Stream
        /// </summary>
        /// 
        /// <returns>RNBWParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());

            writer.Write((int)m_rndEngine);
            writer.Write(m_oId);
            writer.Write(_VI.Length);
            byte[] data = ArrayUtils.ToBytes(_VI);
            writer.Write(data);
            writer.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes the RNBWParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the RNBWParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if The output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("RNBWParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the RNBWParameters to a Stream
        /// </summary>
        /// 
        /// <param name="Output">The Output stream receiving the encoded Parameters</param>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException e)
            {
                throw new CryptoAsymmetricException(e.Message);
            }
        }
        #endregion

        #region Private Methods
        private bool CheckParams()
        {
            if (_VI == null)
                return false;
            if (_VI.Length < 1)
                return false;

            for (int i = 0; i < _VI.Length - 1; i++)
            {
                if (_VI[i] >= _VI[i + 1])
                    return false;
            }

            return true;
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
            int  hash = ArrayUtils.GetHashCode(_VI);
            hash += 31 * (int)m_rndEngine;
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
            if (Obj == null && this != null)
                return false;

            RNBWParameters other = (RNBWParameters)Obj;

            if (!Compare.IsEqual(_VI, other.Vi))
                return false;
            if (m_rndEngine != other.RandomEngine)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this RNBWParameters instance
        /// </summary>
        /// 
        /// <returns>The RNBWParameters copy</returns>
        public object Clone()
        {
            return new RNBWParameters(m_oId, _VI, m_rndEngine);
        }

        /// <summary>
        /// Create a deep copy of this RNBWParameters instance
        /// </summary>
        /// 
        /// <returns>The RNBWParameters copy</returns>
        public object DeepCopy()
        {
            return new RNBWParameters(ToStream());
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
                    m_rndEngine = Prngs.CTRPrng;
                    if (m_oId != null)
                    {
                        Array.Clear(m_oId, 0, m_oId.Length);
                        m_oId = null;
                    }
                    if (_VI != null)
                    {
                        Array.Clear(_VI, 0, _VI.Length);
                        _VI = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
