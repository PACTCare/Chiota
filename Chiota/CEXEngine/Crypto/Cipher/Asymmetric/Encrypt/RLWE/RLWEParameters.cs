#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
    /// Creates, reads and writes parameter settings for RLWEEncrypt.
    /// <para>Predefined parameter sets are available through the <see cref="RLWEParamSets"/> class.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (RLWEParameters mp = new RLWEParameters(512, 12289, 12.18, new byte[] { 2, 5, 1 }))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEEncrypt"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>RLWE Parameter Description:</description>
    /// <para>The current implementation uses pre-generated lookup tables for speed, 
    /// because of this only two base parameter sets are currently supported: N256Q7681 and N512Q12289.
    /// </para>
    /// <list type="table">
    /// <item><description>OId - .</description></item>
    /// <item><description>N - The number of coefficients.</description></item>
    /// <item><description>Q - The Q modulus.</description></item>
    /// <item><description>Sigma - The Sigma value.</description></item>
    /// <item><description>OId - Three bytes that uniquely identify the parameter set.</description></item>
    /// <item><description>MFP - The number of random bytes to prepend to the message.</description></item>
    /// <item><description>Engine - The Prng engine.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Efficient Software Implementation of <a href="https://eprint.iacr.org/2014/725.pdf">Ring-LWE Encryption</a></description></item>
    /// <item><description>Compact Ring-LWE <a href="http://www.cosic.esat.kuleuven.be/publications/article-2444.pdf">Cryptoprocessor</a></description></item>
    /// <item><description>A Simple <a href="http://eprint.iacr.org/2012/688.pdf">Provably Secure Key Exchange</a> Scheme Based on the Learning with Errors Problem</description></item>
    /// <item><description>The <a href="http://www.egr.unlv.edu/~bein/pubs/knuthyaotalg.pdf">Knuth-Yao Quadrangle-Inequality Speedup</a> is a Consequence of Total-Monotonicity</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Ring-LWE-Encryption C version: <a href="https://github.com/ruandc/Ring-LWE-Encryption">ruandc/Ring-LWE-Encryption</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class RLWEParameters : IAsymmetricParameters
    {
        #region Constants
        // The default prepended message padding length
        private const int DEFAULT_MFP = 0;
        // The default number of coefficients
        private const int DEFAULT_N = 512;
        // The default modulus
        private const int DEFAULT_Q = 12289;
        // The default sigma value
        private const double DEFAULT_SIGMA = 12.18;
        private const int OID_SIZE = 4;
        private const string ALG_NAME = "RLWEParameters";
        #endregion

        #region Fields
        private int m_N;
        private int m_Q;
        private double m_Sigma;
        private int m_mFp;
        private byte[] m_oId = new byte[OID_SIZE];
        private bool m_isDisposed = false;
        private Digests m_dgtEngineType = Digests.SHA512;
        private Prngs m_rndEngineType = Prngs.CTRPrng;
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
        /// The digest engine powering the PBPrng used to generate a key; used with the RLWEKeyGenerator:GenerateKeyPair(byte[] Passphrase, byte[] Salt) method.
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid digest is specified</exception>
        public Digests Digest
        {
            get { return m_dgtEngineType; }
            private set { m_dgtEngineType = value; }
        }

        /// <summary>
        /// Get: Three bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return m_oId; }
            private set { m_oId = value; }
        }

        /// <summary>
        /// The number of random bytes to prepend to the message
        /// </summary>
        public int MFP
        {
            get { return m_mFp; }
        }

        /// <summary>
        /// Returns the number of coefficients
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// Return the modulus
        /// </summary>
        public int Q
        {
            get { return m_Q; }
        }

        /// <summary>
        /// The random engine used by SecureRandom
        /// </summary>
        public Prngs RandomEngine
        {
            get { return m_rndEngineType; }
            private set {m_rndEngineType = value; }
        }

        /// <summary>
        /// Returns the sigma value
        /// </summary>
        public double Sigma
        {
            get { return m_Sigma; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Set the default parameters (N:512, Q:12289, Sigma:12.18)
        /// </summary>
        /// 
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="Engine">The PRNG engine used to power SecureRandom</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if <c>N</c>, or <c>Q</c>, or the Oid are invalid</exception>
        public RLWEParameters(byte[] OId, Prngs Engine = Prngs.CTRPrng) :
            this(OId, DEFAULT_N, DEFAULT_Q, DEFAULT_SIGMA)
        {
            this.RandomEngine = Engine;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The Ring-LWE family must be <c>3</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Q">The Q modulus</param>
        /// <param name="Sigma">The Sigma value</param>
        /// <param name="MFP">The number of random bytes to prepend to the message</param>
        /// <param name="Engine">The PRNG engine used to power Random Generation</param>
        /// <param name="PBDigest">The digest engine used to power a Passphrase Based Prng</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if <c>N</c>, or <c>Q</c>, or the Oid are invalid</exception>
        public RLWEParameters(byte[] OId, int N, int Q, double Sigma, int MFP = DEFAULT_MFP, Prngs Engine = Prngs.CTRPrng, Digests PBDigest = Digests.SHA512)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("RLWEParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.RingLWE)
                throw new CryptoAsymmetricException("RLWEParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.RingLWE, new ArgumentException()));
            if (N != 256 && N != 512)
                throw new CryptoAsymmetricException("RLWEParameters:Ctor", "N is invalid (only 256 or 512 currently supported)!", new ArgumentOutOfRangeException());
            if (Q != 7681 && Q != 12289)
                throw new CryptoAsymmetricException("RLWEParameters:Ctor", "Q is invalid (only 7681 or 12289 currently supported)!", new ArgumentOutOfRangeException());
            if (Sigma != 11.31 && Sigma != 12.18)
                throw new CryptoAsymmetricException("RLWEParameters:Ctor", "Sigma is invalid (only 11.31 or 12.18 currently supported)!", new ArgumentOutOfRangeException());
            if (N == 256 && MFP > 16 || N == 512 && MFP > 32)
                throw new CryptoAsymmetricException("RLWEParameters:Ctor", "MFP is invalid (forward padding can not be longer than half the maximum message size)!", new ArgumentOutOfRangeException());

            m_Sigma = Sigma;
            m_N = N;
            m_Q = Q;
            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            m_mFp = MFP;
            m_rndEngineType = Engine;
            m_dgtEngineType = PBDigest;
        }

        /// <summary>
        /// Builds a parameter set from an encoded input stream
        /// </summary>
        /// 
        /// <param name="ParamStream">Stream containing a parameter set</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public RLWEParameters(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                try
                {
                    m_oId = reader.ReadBytes(OID_SIZE);
                    m_N = reader.ReadInt32();
                    m_Q = reader.ReadInt32();
                    m_Sigma = reader.ReadDouble();
                    m_mFp = reader.ReadInt32();
                    m_rndEngineType = (Prngs)reader.ReadInt32();
                    m_dgtEngineType = (Digests)reader.ReadInt32();
                }
                catch
                {
                    throw;
                }

            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("RLWEParameters:CTor", "The stream could not be read!", ex);
            }
        }

        /// <summary>
        /// Builds a parameter set from an encoded byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">Byte array containing a parameter set</param>
        public RLWEParameters(byte[] ParamArray) :
            this(new MemoryStream(ParamArray))
        {
        }

        private RLWEParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEParameters()
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
        /// <returns>An initialized RLWEParameters class</returns>
        public static RLWEParameters From(byte[] ParamArray)
        {
            return new RLWEParameters(ParamArray);
        }

        /// <summary>
        /// Read an encoded Parameters set from a Stream
        /// </summary>
        /// 
        /// <param name="ParamStream">The Stream containing the encoded Parameter set</param>
        /// 
        /// <returns>An initialized RLWEParameters class</returns>
        public static RLWEParameters From(Stream ParamStream)
        {
            return new RLWEParameters(ParamStream);
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded byte array
        /// </summary>
        /// 
        /// <returns>RLWEParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded Stream
        /// </summary>
        /// 
        /// <returns>RLWEParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(m_oId);
            writer.Write(m_N);
            writer.Write(m_Q);
            writer.Write(m_Sigma);
            writer.Write(m_mFp);
            writer.Write((int)m_rndEngineType);
            writer.Write((int)m_dgtEngineType);
            writer.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes the RLWEParameters to a byte array
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
        /// Writes the RLWEParameters to a byte array
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
                throw new CryptoAsymmetricException("RLWEParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the RLWEParameters to a Stream
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

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * m_N;
            hash += 31 * m_Q;
            hash += 31 * m_mFp;
            hash += (int)Math.Round(31 * m_Sigma);
            hash += 31 * (int)m_rndEngineType;
            hash += 31 * (int)m_dgtEngineType;

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

            RLWEParameters other = (RLWEParameters)Obj;

            if (m_N != other.N)
                return false;
            if (m_Q != other.Q)
                return false;
            if (m_rndEngineType != other.RandomEngine)
                return false;
            if (m_dgtEngineType != other.Digest)
                return false;
            if (m_Sigma != other.Sigma)
                return false;
            if (m_mFp != other.MFP)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this RLWEParameters instance
        /// </summary>
        /// 
        /// <returns>The RLWEParameters copy</returns>
        public object Clone()
        {
            return new RLWEParameters(m_oId, m_N, m_Q, m_Sigma, m_mFp, m_rndEngineType, m_dgtEngineType);
        }

        /// <summary>
        /// Create a deep copy of this RLWEParameters instance
        /// </summary>
        /// 
        /// <returns>The RLWEParameters copy</returns>
        public object DeepCopy()
        {
            return new RLWEParameters(ToStream());
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
                    m_Sigma = 0;
                    m_mFp = 0;
                    m_rndEngineType = Prngs.CTRPrng;
                    m_dgtEngineType = Digests.SHA512;

                    if (m_oId != null)
                    {
                        Array.Clear(m_oId, 0, m_oId.Length);
                        m_oId = null;
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
