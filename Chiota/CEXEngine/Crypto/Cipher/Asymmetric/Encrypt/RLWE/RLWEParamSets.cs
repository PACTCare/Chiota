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
    /// Contains sets of predefined Ring-LWE parameters.
    /// <para>Use the FromId(byte[]) or FromName(RLWEParamSets) to return a deep copy of a parameter set.</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <description>Parameter OId:</description>
    /// <list type="bullet">
    /// <item><description>A Parameter Set OId (uniquely identifies the parameter set), is always the first four bytes of a serialized parameter set.</description></item>
    /// <item><description>The OId format is ordered as: <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Unique</c>.</description></item>
    /// <item><description>A Ring-LWE parameters Family designator (first byte) is always the value <c>3</c>, and corresponds to its entry in the AsymmetricEngines enumeration.</description></item>
    /// <item><description>The remaining bytes can be a unique designator.</description></item>
    /// </list>
    /// 
    /// <description>Ring-LWE Parameter Description:</description>
    /// <list type="table">
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
    /// </remarks>
    public static class RLWEParamSets
    {
        #region Enums
        /// <summary>
        /// Set id is defined as: N: coefficients, Q: Modulus
        /// </summary>
        public enum RLWEParamNames : int
        {
            /// <summary>
            /// Low security; uses CSPPrng as the default Prng.
            /// <para>Security:120, MaxText:32, N:256 Q:7681, S:11.31, PublicKey Size:1036, PrivateKey Size:520, OId: 3, 2, 2, 1</para>
            /// </summary>
            N256Q7681 = 1,
            /// <summary>
            /// High security; uses CSPPrng as the default Prng.
            /// <para>Security:240, MaxText:64, N:512 Q:12289, S:12.18, PublicKey Size:2060, PrivateKey Size:1032, OId: 3, 2, 5, 2</para>
            /// </summary>
            N512Q12289 = 2,
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
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is used.</exception>
        public static RLWEParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new CryptoAsymmetricException("RLWEParamSets:FromId", "OId can not be null!", new ArgumentNullException());
            if (OId.Length != 4)
                throw new CryptoAsymmetricException("RLWEParamSets:FromId", "OId must be 4 bytes in length!", new ArgumentOutOfRangeException());
            if (OId[0] != (byte)AsymmetricEngines.RingLWE)
                throw new CryptoAsymmetricException("RLWEParamSets:FromId", "OId is not a valid RLWE parameter id!", new ArgumentException());

            if (OId[3] == 1)
                return (RLWEParameters)RLWEN256Q7681.DeepCopy();
            else if (OId[3] == 2)
                return (RLWEParameters)RLWEN512Q12289.DeepCopy();

            throw new CryptoAsymmetricException("RLWEParamSets:FromId", "OId does not identify a valid param set!", new ArgumentOutOfRangeException());
        }

        /// <summary>
        /// Retrieve a parameter set by its enumeration name
        /// </summary>
        /// 
        /// <param name="ParamName">The enumeration name</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static RLWEParameters FromName(RLWEParamNames ParamName)
        {
            switch (ParamName)
            {
                case RLWEParamNames.N256Q7681:
                    return (RLWEParameters)RLWEN256Q7681.DeepCopy();
                case RLWEParamNames.N512Q12289:
                    return (RLWEParameters)RLWEN512Q12289.DeepCopy();
                default:
                    throw new CryptoAsymmetricException("RLWEParamSets:FromName", "The enumeration name is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get a serialized RLWEParameters class from a parameter name
        /// </summary>
        /// 
        /// <param name="ParamName">The Ring-LWE Parameters set name</param>
        /// 
        /// <returns>The serialized RLWEParameters set</returns>
        public static byte[] GetFormatted(RLWEParamNames ParamName)
        {
            return FromName(ParamName).ToBytes();
        }

        /// <summary>
        /// Retrieve the OId for a parameter set
        /// </summary>
        /// 
        /// <param name="ParamName">The enumeration name</param>
        /// 
        /// <returns>The 4 byte OId field</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static byte[] GetID(RLWEParamNames ParamName)
        {
            switch (ParamName)
            {
                case RLWEParamNames.N256Q7681:
                    return new byte[] { (byte)AsymmetricEngines.RingLWE, 2, 2, 1 };
                case RLWEParamNames.N512Q12289:
                    return new byte[] { (byte)AsymmetricEngines.RingLWE, 2, 5, 2 };
                default:
                    throw new CryptoAsymmetricException("RLWEParamSets:GetID", "The enumeration name is unknown!", new ArgumentException());
            }
        }
        #endregion

        #region Parameter Sets
        // Note: Oid = family, N-base, ordinal
        /// <summary>
        /// Medium security; uses CSPPrng as the default Prng.
        /// <para>Security:120, MaxText:32, N:256 Q:7681, S:11.31, PublicKey Size:1036, PrivateKey Size:520, OId: 3, 2, 2, 1</para>
        /// </summary>
        public static RLWEParameters RLWEN256Q7681 = new RLWEParameters(new byte[] { (byte)AsymmetricEngines.RingLWE, 2, 2, 1 }, 256, 7681, 11.31);

        /// <summary>
        /// High security; uses CSPPrng as the default Prng.
        /// <para>Security:240, MaxText:64, N:512 Q:12289, S:12.18, PublicKey Size:2060, PrivateKey Size:1032, OId: 3, 2, 5, 2</para>
        /// </summary>
        public static RLWEParameters RLWEN512Q12289 = new RLWEParameters(new byte[] { (byte)AsymmetricEngines.RingLWE, 2, 5, 2 }, 512, 12289, 12.18);
        #endregion
    }
}
