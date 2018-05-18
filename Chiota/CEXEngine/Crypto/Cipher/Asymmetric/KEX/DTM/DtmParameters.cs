#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The GPL Version 3 License
// 
// Copyright (C) 2015 John Underhill
// This file is part of the CEX Cryptographic library.
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
// Written by John Underhill, August 21, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM
{
    #region DtmParameters
    /// <summary>
    /// The DtmParameters class.
    /// <para>The DtmParameters class is used to define the working parameters used by the DTM Key Exchange using a DtmKex instance.</para>
    /// <para>The bytes <c>0</c> through <c>3</c> are the Auth-Phase asymmetric parameters OId.
    /// The next 4 bytes are the Primary-Phase asymmetric parameters OId.
    /// Bytes <c>8</c> and <c>9</c> identify the Auth-Phase DtmSessionStruct symmetric cipher parameters.
    /// Bytes <c>10</c> and <c>11</c> identify the Primary-Phase DtmSessionStruct symmetric cipher parameters.
    /// The last <c>4</c> bytes are used to uniquely identify the parameter set.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmClientStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmIdentityStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmSessionStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex"/>
    public sealed class DtmParameters : IDisposable, ICloneable
    {
        #region Private Fields
        private bool m_isDisposed = false;
        #endregion

        #region Public Fields <c></c>
        /// <summary>
        /// The DtmParameters Identifier field; should be 16 bytes describing the parameter set (see class notes)
        /// </summary>
        public byte[] OId;
        /// <summary>
        /// The <c>Auth-Phase</c> Asymmetric parameters OId; can be the Asymmetric cipher parameters OId, or a serialized Asymmetric Parameters class
        /// </summary>
        public byte[] AuthPkeId;
        /// <summary>
        /// The <c>Primary-Phase</c> Asymmetric parameters OId; can be the Asymmetric cipher parameters OId, or a serialized Asymmetric Parameters class
        /// </summary>
        public byte[] PrimaryPkeId;
        /// <summary>
        /// The <c>Auth-Phase</c> Symmetric sessions cipher parameters; contains a complete description of the Symmetric cipher
        /// </summary>
        public DtmSessionStruct AuthSession;
        /// <summary>
        /// The <c>Primary-Phase</c> Symmetric sessions cipher parameters; contains a complete description of the Symmetric cipher
        /// </summary>
        public DtmSessionStruct PrimarySession;
        /// <summary>
        /// The Prng type used to pad messages
        /// </summary>
        public Prngs RandomEngine;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to append to the <c>Primary-Phase</c> Asymmetric Public key before encryption
        /// </summary>
        public int MaxAsmKeyAppend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to prepend to the <c>Primary-Phase</c> Asymmetric Public key before encryption
        /// </summary>
        public int MaxAsmKeyPrePend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to append to the <c>Primary-Phase</c> Client Identity before encryption
        /// </summary>
        public int MaxAsmParamsAppend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to prepend to the <c>Primary-Phase</c> Asymmetric Client Identity before encryption
        /// </summary>
        public int MaxAsmParamsPrePend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to append to the <c>Primary-Phase</c> Symmetric key before encryption
        /// </summary>
        public int MaxSymKeyAppend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to prepend to the <c>Primary-Phase</c> Symmetric key before encryption
        /// </summary>
        public int MaxSymKeyPrePend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to append to a <c>Post-Exchange</c> message before encryption
        /// </summary>
        public int MaxMessageAppend;
        /// <summary>
        /// (Optional) The maximum number of pseudo-random bytes to prepend to a <c>Post-Exchange</c> message before encryption
        /// </summary>
        public int MaxMessagePrePend;
        /// <summary>
        /// (Optional) The maximum delay time before sending the <c>Primary-Phase</c> Asymmetric key; the minimum time is 1 half max, a value of <c>0</c> has no delay 
        /// </summary>
        public int MaxAsmKeyDelayMS;
        /// <summary>
        /// (Optional) The maximum delay time before sending the <c>Primary-Phase</c> Symmetric key; the minimum time is 1 half max, a value of <c>0</c> has no delay
        /// </summary>
        public int MaxSymKeyDelayMS;
        /// <summary>
        /// (Optional) The maximum delay time before sending <c>Post-Exchange</c> message traffic; the minimum time is <c>0</c>, a value of <c>0</c> has no delay
        /// </summary>
        public int MaxMessageDelayMS;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmParameters primary constructor
        /// </summary>
        /// 
        /// <param name="OId">The DtmParameters Identifier field; must be 16 bytes in length</param>
        /// <param name="AuthPkeId">The <c>Auth-Phase</c> Asymmetric parameters OId; can be the Asymmetric cipher parameters OId, or a serialized Asymmetric Parameters class</param>
        /// <param name="PrimaryPkeId">The <c>Primary-Phase</c> Asymmetric parameters OId; can be the Asymmetric cipher parameters OId, or a serialized Asymmetric Parameters class</param>
        /// <param name="AuthSession">The <c>Auth-Phase</c> Symmetric sessions cipher parameters; contains a complete description of the Symmetric cipher</param>
        /// <param name="PrimarySession">The <c>Primary-Phase</c> Symmetric sessions cipher parameters; contains a complete description of the Symmetric cipher</param>
        /// <param name="RandomEngine">(Optional) The Prng used to pad messages, defaults to CTRPrng</param>
        /// <param name="MaxAsmKeyAppend">(Optional) The maximum number of pseudo-random bytes to append to the <c>Primary-Phase</c> Asymmetric Public key before encryption</param>
        /// <param name="MaxAsmKeyPrePend">(Optional) The maximum number of pseudo-random bytes to prepend to the <c>Primary-Phase</c> Asymmetric Public key before encryption</param>
        /// <param name="MaxAsmParamsAppend">(Optional) The maximum number of pseudo-random bytes to append to the <c>Primary-Phase</c> Client Identity before encryption</param>
        /// <param name="MaxAsmParamsPrePend">(Optional) The maximum number of pseudo-random bytes to prepend to the <c>Primary-Phase</c> Asymmetric Client Identity before encryption</param>
        /// <param name="MaxSymKeyAppend">(Optional) The maximum number of pseudo-random bytes to append to the <c>Primary-Phase</c> Symmetric key before encryption</param>
        /// <param name="MaxSymKeyPrePend">(Optional) The maximum number of pseudo-random bytes to prepend to the <c>Primary-Phase</c> Symmetric key before encryption</param>
        /// <param name="MaxMessageAppend">(Optional) The maximum number of pseudo-random bytes to append to a <c>Post-Exchange</c> message before encryption</param>
        /// <param name="MaxMessagePrePend">(Optional) The maximum number of pseudo-random bytes to prepend to a <c>Post-Exchange</c> message before encryption</param>
        /// <param name="MaxAsmKeyDelayMS">(Optional) The maximum delay time before sending the <c>Primary-Phase</c> Asymmetric key; the minimum time is 1 half max, a value of <c>0</c> has no delay</param>
        /// <param name="MaxSymKeyDelayMS">(Optional) The maximum delay time before sending the <c>Primary-Phase</c> Symmetric key; the minimum time is 1 half max, a value of <c>0</c> has no delay</param>
        /// <param name="MaxMessageDelayMS">(Optional) The maximum delay time before sending message traffic; the minimum time is <c>0</c>, a value of <c>0</c> has no delay</param>
        public DtmParameters(byte[] OId, byte[] AuthPkeId, byte[] PrimaryPkeId, DtmSessionStruct AuthSession, DtmSessionStruct PrimarySession, Prngs RandomEngine = Prngs.CTRPrng, int MaxAsmKeyAppend = 0, int MaxAsmKeyPrePend = 0, int MaxAsmParamsAppend = 0, 
            int MaxAsmParamsPrePend = 0, int MaxSymKeyAppend = 0, int MaxSymKeyPrePend = 0, int MaxMessageAppend = 0, int MaxMessagePrePend = 0, int MaxAsmKeyDelayMS = 0, int MaxSymKeyDelayMS = 0, int MaxMessageDelayMS = 0)
        {
            this.OId = OId;
            this.AuthPkeId = AuthPkeId;
            this.PrimaryPkeId = PrimaryPkeId;
            this.AuthSession = AuthSession;
            this.PrimarySession = PrimarySession;
            this.RandomEngine = RandomEngine;
            this.MaxAsmKeyAppend = MaxAsmKeyAppend;
            this.MaxAsmKeyPrePend = MaxAsmKeyPrePend;
            this.MaxAsmParamsAppend = MaxAsmParamsAppend;
            this.MaxAsmParamsPrePend = MaxAsmParamsPrePend;
            this.MaxSymKeyAppend = MaxSymKeyAppend;
            this.MaxSymKeyPrePend = MaxSymKeyPrePend;
            this.MaxMessageAppend = MaxMessageAppend;
            this.MaxMessagePrePend = MaxMessagePrePend;
            this.MaxAsmKeyDelayMS = MaxAsmKeyDelayMS;
            this.MaxSymKeyDelayMS = MaxSymKeyDelayMS;
            this.MaxMessageDelayMS = MaxMessageDelayMS;
        }

        /// <summary>
        /// Constructs a DtmParameters from a byte array
        /// </summary>
        /// 
        /// <param name="ParametersArray">The byte array containing the DtmParameters structure</param>
        public DtmParameters(byte[] ParametersArray) :
            this(new MemoryStream(ParametersArray))
        {
        }

        /// <summary>
        /// Constructs a DtmIdentityStruct from a stream
        /// </summary>
        /// 
        /// <param name="ParametersStream">Stream containing a serialized DtmParameters</param>
        /// 
        /// <returns>A populated DtmParameters</returns>
        public DtmParameters(Stream ParametersStream)
        {
            BinaryReader reader = new BinaryReader(ParametersStream);
            int len;
            byte[] data;

            len = reader.ReadInt32();
            OId = reader.ReadBytes(len);
            len = reader.ReadInt32();
            AuthPkeId = reader.ReadBytes(len);
            len = reader.ReadInt32();
            PrimaryPkeId = reader.ReadBytes(len);
            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            AuthSession = new DtmSessionStruct(data);
            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            PrimarySession = new DtmSessionStruct(data);
            RandomEngine = (Prngs)reader.ReadByte();
            MaxAsmKeyAppend = reader.ReadInt32();
            MaxAsmKeyPrePend = reader.ReadInt32();
            MaxAsmParamsAppend = reader.ReadInt32();
            MaxAsmParamsPrePend = reader.ReadInt32();
            MaxSymKeyAppend = reader.ReadInt32();
            MaxSymKeyPrePend = reader.ReadInt32();
            MaxMessageAppend = reader.ReadInt32();
            MaxMessagePrePend = reader.ReadInt32();
            MaxAsmKeyDelayMS = reader.ReadInt32();
            MaxSymKeyDelayMS = reader.ReadInt32();
            MaxMessageDelayMS = reader.ReadInt32();
        }

        private DtmParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DtmParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Deserialize an DtmParameters
        /// </summary>
        /// 
        /// <param name="ParametersStream">Stream containing a serialized DtmParameters</param>
        /// 
        /// <returns>A populated DtmParameters</returns>
        public static DtmParameters DeSerialize(Stream ParametersStream)
        {
            return new DtmParameters(ParametersStream);
        }

        /// <summary>
        /// Serialize an DtmParameters structure
        /// </summary>
        /// 
        /// <param name="Paramaters">A DtmParameters structure</param>
        /// 
        /// <returns>A stream containing the DtmParameters data</returns>
        public static Stream Serialize(DtmParameters Paramaters)
        {
            return Paramaters.ToStream();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the class Size in bytes
        /// </summary>
        /// 
        /// <returns>Serialized class size</returns>
        public int GetHeaderSize()
        {
            return (int)Serialize(this).Length;
        }

        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            Array.Clear(OId, 0, OId.Length);
            Array.Clear(AuthPkeId, 0, AuthPkeId.Length);
            Array.Clear(PrimaryPkeId, 0, PrimaryPkeId.Length);
            AuthSession.Reset();
            PrimarySession.Reset();
            RandomEngine = Prngs.CTRPrng;
            MaxAsmKeyAppend = 0;
            MaxAsmKeyPrePend = 0;
            MaxAsmParamsAppend = 0;
            MaxAsmParamsPrePend = 0;
            MaxSymKeyAppend = 0;
            MaxSymKeyPrePend = 0;
            MaxMessageAppend = 0;
            MaxMessagePrePend = 0;
            MaxAsmKeyDelayMS = 0;
            MaxSymKeyDelayMS = 0;
            MaxMessageDelayMS = 0;
        }
        /// <summary>
        /// Returns the DtmParameters as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmParameters</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmParameters as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmParameters</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);
            byte[] data;

            writer.Write(OId.Length);
            writer.Write(OId);
            writer.Write(AuthPkeId.Length);
            writer.Write(AuthPkeId);
            writer.Write(PrimaryPkeId.Length);
            writer.Write(PrimaryPkeId);
            data = AuthSession.ToBytes();
            writer.Write(data.Length);
            writer.Write(data);
            data = PrimarySession.ToBytes();
            writer.Write(data.Length);
            writer.Write(data);
            writer.Write((byte)RandomEngine);
            writer.Write(MaxAsmKeyAppend);
            writer.Write(MaxAsmKeyPrePend);
            writer.Write(MaxSymKeyAppend);
            writer.Write(MaxAsmParamsAppend);
            writer.Write(MaxAsmParamsPrePend);
            writer.Write(MaxSymKeyPrePend);
            writer.Write(MaxMessageAppend);
            writer.Write(MaxMessagePrePend);
            writer.Write(MaxAsmKeyDelayMS);
            writer.Write(MaxSymKeyDelayMS);
            writer.Write(MaxMessageDelayMS);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
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
            int hash = ArrayUtils.GetHashCode(OId);
            hash += ArrayUtils.GetHashCode(AuthPkeId);
            hash += ArrayUtils.GetHashCode(PrimaryPkeId);
            hash += 31 * PrimarySession.EngineType;
            hash += 31 * PrimarySession.IvSize;
            hash += 31 * PrimarySession.KdfEngine;
            hash += 31 * PrimarySession.KeySize;
            hash += 31 * PrimarySession.RoundCount;
            hash += 31 * AuthSession.EngineType;
            hash += 31 * AuthSession.IvSize;
            hash += 31 * AuthSession.KdfEngine;
            hash += 31 * AuthSession.KeySize;
            hash += 31 * AuthSession.RoundCount;
            hash += 31 * (int)RandomEngine;
            hash += 31 * MaxAsmKeyAppend;
            hash += 31 * MaxAsmKeyPrePend;
            hash += 31 * MaxAsmParamsAppend;
            hash += 31 * MaxAsmParamsPrePend;
            hash += 31 * MaxSymKeyAppend;
            hash += 31 * MaxSymKeyPrePend;
            hash += 31 * MaxMessageAppend;
            hash += 31 * MaxMessagePrePend;
            hash += 31 * MaxAsmKeyDelayMS;
            hash += 31 * MaxSymKeyDelayMS;
            hash += 31 * MaxMessageDelayMS;

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

            DtmParameters other = (DtmParameters)Obj;
            if (GetHashCode() != other.GetHashCode())
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this DtmParameters instance
        /// </summary>
        /// 
        /// <returns>The DtmParameters copy</returns>
        public object Clone()
        {
            return new DtmParameters(OId, AuthPkeId, PrimaryPkeId, AuthSession, PrimarySession, RandomEngine, MaxAsmKeyAppend, MaxAsmKeyPrePend, MaxAsmParamsAppend, MaxAsmParamsPrePend, 
                MaxSymKeyAppend, MaxSymKeyPrePend, MaxMessageAppend, MaxMessagePrePend, MaxAsmKeyDelayMS, MaxSymKeyDelayMS, MaxMessageDelayMS);
        }

        /// <summary>
        /// Create a deep copy of this DtmParameters instance
        /// </summary>
        /// 
        /// <returns>The DtmParameters copy</returns>
        public object DeepCopy()
        {
            return new DtmParameters(ToStream());
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
                    Reset();
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
    #endregion
}
