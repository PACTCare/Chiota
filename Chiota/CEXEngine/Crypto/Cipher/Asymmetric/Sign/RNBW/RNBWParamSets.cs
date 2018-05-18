#region Directives
using System;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
    /// Contains sets of predefined Rainbow parameters.
    /// <para>Use the FromId(byte[]) or FromName(RNBWParamSets) to return a deep copy of a parameter set.</para>
    /// </summary>
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
    /// <description>Parameter Sets:</description>
    /// <list type="table">
    /// <listheader>
    ///     <term>Strength</term>
    ///     <term>N</term>
    ///     <term>V1, V2, V3, V4</term>
    /// </listheader>
    /// 
    /// <item><description>Low</description></item>
    /// <item><description>33</description></item>
    /// <item><description>6, 12, 17, 22</description></item>
    /// 
    /// <item><description>Medium</description></item>
    /// <item><description>49</description></item>
    /// <item><description>19, 26, 32, 38</description></item>
    /// 
    /// <item><description>Medium</description></item>
    /// <item><description>54</description></item>
    /// <item><description>21, 27, 34, 44</description></item>
    /// 
    /// <item><description>High</description></item>
    /// <item><description>58</description></item>
    /// <item><description>24, 30, 37, 44</description></item>
    /// 
    /// <item><description>High</description></item>
    /// <item><description>60</description></item>
    /// <item><description>24, 30, 37, 45</description></item>
    /// 
    /// <item><description>High</description></item>
    /// <item><description>63</description></item>
    /// <item><description>26, 33, 40, 51</description></item>
    /// 
    /// <item><description>High</description></item>
    /// <item><description>66</description></item>
    /// <item><description>27, 35, 43, 54</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Selecting Parameters for the <a href="http://eprint.iacr.org/2010/437.pdf">Rainbow Signature Scheme</a></description></item>
    /// </list>
    /// </remarks>
    public static class RNBWParamSets
    {
        #region Enums
        /// <summary>
        /// Set id is defined as: N: coefficients, L: vinegar count
        /// </summary>
        public enum RNBWParamNames : int
        {
            /// <summary>
            /// Medium security.
            /// <para>N: 33, VI: 6, 12, 17, 22, PublicKey Size: 32162, PrivateKey Size: 27896</para>
            /// </summary>
            N33L5,
            /// <summary>
            /// Medium security. 
            /// <para>N: 49, VI: 19, 26, 32, 38, PublicKey Size: 76532, PrivateKey Size: 81858</para>
            /// </summary>
            N49L5,
            /// <summary>
            /// Medium security. 
            /// <para>N: 54, VI: 21, 27, 34, 44, PublicKey Size: 101672, PrivateKey Size: 108406</para>
            /// </summary>
            N54L5,
            /// <summary>
            /// High security.
            /// <para>N: 58, VI: 24, 30, 37, 44, PublicKey Size: 120392, PrivateKey Size: 131138</para>
            /// </summary>
            N58L5,
            /// <summary>
            /// High security.
            /// <para>N: 60, VI: 24, 30, 37, 45, PublicKey Size: 136184, PrivateKey Size: 145574</para>
            /// </summary>
            N60L5,
            /// <summary>
            /// High security.
            /// <para>N: 63, VI: 26, 33, 40, 51, PublicKey Size: 153952, PrivateKey Size: 167390</para>
            /// </summary>
            N63L5,
            /// <summary>
            /// High security.
            /// <para>N: 66, VI: 27, 35, 43, 54, PublicKey Size: 177716, PrivateKey Size: 192182</para>
            /// </summary>
            N66L5
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a parameter set by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 4 byte parameter set identity code</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static RNBWParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new CryptoAsymmetricException("RNBWParamSets:FromId", "OId can not be null!", new ArgumentException());
            if (OId.Length != 4)
                throw new CryptoAsymmetricException("RNBWParamSets:FromId", "OId must be 4 bytes in length!", new ArgumentException());
            if (OId[0] != (byte)AsymmetricEngines.Rainbow)
                throw new CryptoAsymmetricException("RNBWParamSets:FromId", "OId is not a valid Rainbow parameter id!", new ArgumentException());

            if (OId[3] == 1)
                return (RNBWParameters)RNBWN33L5.DeepCopy();
            else if (OId[3] == 2)
                return (RNBWParameters)RNBWN49L5.DeepCopy();
            else if (OId[3] == 3)
                return (RNBWParameters)RNBWN54L5.DeepCopy();
            else if (OId[3] == 4)
                return (RNBWParameters)RNBWN58L5.DeepCopy();
            else if (OId[3] == 5)
                return (RNBWParameters)RNBWN60L5.DeepCopy();
            else if (OId[3] == 6)
                return (RNBWParameters)RNBWN63L5.DeepCopy();
            else if (OId[3] == 7)
                return (RNBWParameters)RNBWN66L5.DeepCopy();
            else
                throw new CryptoAsymmetricException("RNBWParamSets:FromId", "OId does not identify a valid param set!", new ArgumentException());
        }

        /// <summary>
        /// Retrieve a parameter set by its enumeration name
        /// </summary>
        /// 
        /// <param name="ParamName">The enumeration name</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static RNBWParameters FromName(RNBWParamNames ParamName)
        {
            switch (ParamName)
            {
                case RNBWParamNames.N33L5:
                    return (RNBWParameters)RNBWN33L5.DeepCopy();
                case RNBWParamNames.N49L5:
                    return (RNBWParameters)RNBWN49L5.DeepCopy();
                case RNBWParamNames.N54L5:
                    return (RNBWParameters)RNBWN54L5.DeepCopy();
                case RNBWParamNames.N58L5:
                    return (RNBWParameters)RNBWN58L5.DeepCopy();
                case RNBWParamNames.N60L5:
                    return (RNBWParameters)RNBWN60L5.DeepCopy();
                case RNBWParamNames.N63L5:
                    return (RNBWParameters)RNBWN63L5.DeepCopy();
                case RNBWParamNames.N66L5:
                    return (RNBWParameters)RNBWN66L5.DeepCopy();
                default:
                    throw new CryptoAsymmetricException("RNBWParamSets:FromName", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get a serialized RNBWParameters class from a parameter name
        /// </summary>
        /// 
        /// <param name="ParamName">The RNBW Parameters set name</param>
        /// 
        /// <returns>The serialized RNBWParameters set</returns>
        public static byte[] GetFormatted(RNBWParamNames ParamName)
        {
            return FromName(ParamName).ToBytes();
        }

        /// <summary>
        /// Retrieve the parameter OId by its enumeration name
        /// </summary>
        /// 
        /// <param name="ParamName">The enumeration name</param>
        /// 
        /// <returns>The 4 byte OId field</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static byte[] GetID(RNBWParamNames ParamName)
        {
            switch (ParamName)
            {
                case RNBWParamNames.N33L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 1, 1 };
                case RNBWParamNames.N49L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 2, 1 };
                case RNBWParamNames.N54L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 3, 1 };
                case RNBWParamNames.N58L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 4, 1 };
                case RNBWParamNames.N60L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 5, 1 };
                case RNBWParamNames.N63L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 6, 1 };
                case RNBWParamNames.N66L5:
                    return new byte[] { (byte)AsymmetricEngines.Rainbow, 1, 7, 1 };
                default:
                    throw new CryptoAsymmetricException("RNBWParamSets:GetID", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }
        #endregion

        #region Parameter Sets
        /// <summary>
        /// Medium security.
        /// <para>N: 33, VI: 6, 12, 17, 22, PublicKey Size: 32162, PrivateKey Size: 27896</para>
        /// </summary>
        public static RNBWParameters RNBWN33L5 = new RNBWParameters(new byte[] { 4, 1, 1, 1 }, new int[] { 6, 12, 17, 22, 33 });
        /// <summary>
        /// Medium security. 
        /// <para>N: 49, VI: 19, 26, 32, 38, PublicKey Size: 76532, PrivateKey Size: 81858</para>
        /// </summary>
        public static RNBWParameters RNBWN49L5 = new RNBWParameters(new byte[] { 4, 1, 2, 1 }, new int[] { 19, 26, 32, 38, 49 });
        /// <summary>
        /// Medium security. 
        /// <para>N: 54, VI: 21, 27, 34, 44, PublicKey Size: 101672, PrivateKey Size: 108406</para>
        /// </summary>
        public static RNBWParameters RNBWN54L5 = new RNBWParameters(new byte[] { 4, 1, 3, 1 }, new int[] { 21, 27, 34, 44, 54 });
        /// <summary>
        /// High security.
        /// <para>N: 58, VI: 24, 30, 37, 44, PublicKey Size: 120392, PrivateKey Size: 131138</para>
        /// </summary>
        public static RNBWParameters RNBWN58L5 = new RNBWParameters(new byte[] { 4, 1, 4, 1 }, new int[] { 24, 30, 37, 44, 58 });
        /// <summary>
        /// High security.
        /// <para>N: 60, VI: 24, 30, 37, 45, PublicKey Size: 136184, PrivateKey Size: 145574</para>
        /// </summary>
        public static RNBWParameters RNBWN60L5 = new RNBWParameters(new byte[] { 4, 1, 5, 1 }, new int[] { 24, 30, 37, 45, 60 });
        /// <summary>
        /// High security.
        /// <para>N: 63, VI: 26, 33, 40, 51, PublicKey Size: 153952, PrivateKey Size: 167390</para>
        /// </summary>
        public static RNBWParameters RNBWN63L5 = new RNBWParameters(new byte[] { 4, 1, 6, 1 }, new int[] { 26, 33, 40, 51, 63 });
        /// <summary>
        /// High security.
        /// <para>N: 66, VI: 27, 35, 43, 54, PublicKey Size: 177716, PrivateKey Size: 192182</para>
        /// </summary>
        public static RNBWParameters RNBWN66L5 = new RNBWParameters(new byte[] { 4, 1, 7, 1 }, new int[] { 27, 35, 43, 54, 66 });
        #endregion
    }
}
