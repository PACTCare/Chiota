#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
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
    /// <summary>
    /// A set of pre-defined DTM parameter sets.
    /// <para>Both hosts in a key exchange must use a parameter set with the same Security Classification.
    /// This is negotiated during the Connect phase of the DTM Key Exchange protocol. See the <see cref="DtmKex"/> class for a description of the exchange.</para>
    /// <para>Set id prefix is defined as: Security Classification <c>X1</c> (maximum security), <c>X2</c> (high security), <c>X3</c> (security and speed), and <c>X4</c> (speed optimized).
    /// The next 2 characters are the first letter of both asymmetric parameter ids. 
    /// This is followed by both symmetric cipher enumeration values and their Kdf engine type (Digests enum member or 0 for none).</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <para>There are four descending security classifications, X1, X2, X3, and X4, with X1 to be considered as the most secure, and X4 as optimized for best performance with standard configurations.
    /// As of the 1.4b release, the asymmetric cipher pairing is static; Ring-LWE for the <c>Authenticaion Phase</c> of the exchange, and NTRU in the <c>Primary Phase</c> of the key exchange.
    /// This will change when additional asymmetric ciphers are added to the library distribution.
    /// The set considered as the strongest in a class is always the first parameter set in the grouping; ex. DTMX11RNS1R2 or X1.1.
    /// The X1 and X2 parameter sets use one of the HX series ciphers (RHX, SHX, THX) as the primary transmission cipher. The HX ciphers use a cryptographically strong 
    /// Key Derivation Function (HKDF) powered by Skein, Keccak, Blake or SHA-2, to create the working keys used by the cipher. 
    /// The HX ciphers also use an increased number of diffusion rounds. HX cipher round counts are 22 for Rijndael, 40 for Serpent, and 20 with Twofish in the X1 and X2 parameter sets. 
    /// The increased number of rounds adds security by creating a more diffused output, strongly mitigating differential and algebraic based attack vectors.</para>
    /// 
    /// <description>Security Classification Definitions:</description>
    /// <list type="bullet">
    /// <item><description>X1: Asymmetric ciphers are Ring-LWE/NTRU, symmetric ciphers using a 256 bit key (auth-phase), and an HKDF/Keccak-512 strengthened HX series cipher (primary-phase).</description></item>
    /// <item><description>X2: Asymmetric ciphers are Ring-LWE/NTRU, symmetric ciphers are a standard series cipher (256 bit key), and an HX/Skein-512 symmetric cipher implementation.</description></item>
    /// <item><description>X3: Asymmetric ciphers are Ring-LWE/NTRU, and symmetric ciphers using 256/512 bit keys (auth/primary).</description></item>
    /// <item><description>X4: Asymmetric ciphers are Ring-LWE/NTRU, and standard symmetric cipher configurations using 256 bit keys.</description></item>
    /// </list>
    /// 
    /// <description>The 16 byte Parameter OId configuration:</description>
    /// <list type="bullet">
    /// <item><description>The bytes <c>0</c> through <c>3</c> are the Auth-Stage asymmetric parameters OId.</description></item>
    /// <item><description>The bytes <c>4</c> through <c>7</c> are the Primary-Stage asymmetric parameters OId.</description></item>
    /// <item><description>Bytes <c>8</c> and <c>9</c> identify the Auth-Stage DtmSessionStruct symmetric cipher parameters.</description></item>
    /// <item><description>Bytes <c>10</c> and <c>11</c> identify the Primary-Stage DtmSessionStruct symmetric cipher parameters.</description></item>
    /// <item><description>The third byte: <c>SubSet</c>, defines the PolyType; simple <c>1</c> or product form <c>2</c>.</description></item>
    /// <item><description>The last <c>4</c> bytes are used to uniquely identify the parameter set.</description></item>
    /// </list>
    /// </remarks>
    public static class DtmParamSets
    {
        #region Enums
        /// <summary>
        /// Set id prefix is defined as: Security Classification <c>X1</c> (maximum security), <c>X2</c> (high security), <c>X3</c> (security and speed), and <c>X4</c> (speed optimized).
        /// <para>The next 2 characters are the first letter of both asymmetric parameter ids. 
        /// This is followed by both symmetric cipher enumeration values and their Kdf engine type (Digests enum member or 0 for none).</para>
        /// </summary>
        public enum DtmParamNames : int
        {
            /// <summary>
            /// Class 1, X1.1 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 powered Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X11RNS1R2 = 1,
            /// <summary>
            /// Class 1, X1.2 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael (AES256).
            /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 powered Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X12RNR1R2,
            /// <summary>
            /// Class 1, X1.3 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 40 rounds of SHX with the Skein-512 powered Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X13RNS1S2,
            /// <summary>
            /// Class 1, X1.4 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
            /// Primary Stage: NTRU and 20 rounds of THX with the Skein-512 powered Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X14RNT1T2,
            /// <summary>
            /// Class 2, X2.1 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X21RNS1R2,
            /// <summary>
            /// Class 2, X2.2 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael (AES256).
            /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X22RNR1R2,
            /// <summary>
            /// Class 2, X2.3 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 40 rounds of SHX with the Skein-512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X23RNS1S2,
            /// <summary>
            /// Class 2, X2.3 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 40 rounds of SHX with the Skein-512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X24RNT1T2,
            /// <summary>
            /// Class 3, X3.1 Configuration: Optimized for security and speed.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent with a 256 bit key.
            /// Primary Stage: NTRU and 22 rounds of Rijndael with a 512 bit key.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X31RNS1R1,
            /// <summary>
            /// Class 3, X3.2 Configuration: Optimized for security and speed.
            /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael with a 256 bit key (AES256).
            /// Primary Stage: NTRU and 22 rounds of Rijndael with a 512 bit key.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X32RNR1R1,
            /// <summary>
            /// Class 3, X3.3 Configuration: Optimized for security and speed.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent with a 256 bit key.
            /// Primary Stage: NTRU and 32 rounds of Serpent with a 512 bit key.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X33RNS1S1,
            /// <summary>
            /// Class 3, X3.4 Configuration: Optimized for security and speed.
            /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish with a 256 bit key.
            /// Primary Stage: NTRU and 20 rounds of Twofish with a 512 bit key.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X34RNT1T1,
            /// <summary>
            /// Class 4, X4.1 Configuration: Optimized for speed.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 14 rounds of Rijndael (AES256).</para>
            /// </summary>
            X41RNS1R1,
            /// <summary>
            /// Class 4, X4.2 Configuration: Optimized for speed.
            /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael (AES256).
            /// Primary Stage: NTRU and 14 rounds of Rijndael (AES256).</para>
            /// </summary>
            X42RNR1R1,
            /// <summary>
            /// Class 4, X4.3 Configuration: Optimized for speed.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 32 rounds of Serpent.</para>
            /// </summary>
            X43RNS1S1,
            /// <summary>
            /// Class 4, X4.4 Configuration: Optimized for speed.
            /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
            /// Primary Stage: NTRU and 16 rounds of Twofish.</para>
            /// </summary>
            X44RNT1T1
        }

        /// <summary>
        /// Represents the security classification of a predefined parameter set
        /// </summary>
        public enum SecurityContexts : int
        {
            /// <summary>
            /// Maximum Security: Set was implemented for a maximum security context
            /// </summary>
            X1 = 1,
            /// <summary>
            /// High Security: Set was implemented for a high security context
            /// </summary>
            X2,
            /// <summary>
            /// Security and Speed: Set was balanced for security and speed
            /// </summary>
            X3,
            /// <summary>
            /// Speed Optimized: Set was optimized for speed
            /// </summary>
            X4
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a DtmParameters by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 16 byte parameter set identity code</param>
        /// 
        /// <returns>A populated DtmParameters parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static DtmParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId can not be null!", new ArgumentException());
            if (OId.Length != 16)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId must be at least 16 bytes in length!", new ArgumentException());
            if (OId[0] != 1 && OId[0] != 2 && OId[0] != 3)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId is not a valid DtmParameters parameter id!", new ArgumentException());
            if (OId[4] != 1 && OId[4] != 2 && OId[4] != 3)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId is not a valid DtmParameters parameter id!", new ArgumentException());
            // x1
            if (Compare.IsEqual(OId, GetID(DtmParamNames.X11RNS1R2)))
                return (DtmParameters)DTMX11RNS1R2.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X12RNR1R2)))
                return (DtmParameters)DTMX12RNR1R2.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X13RNS1S2)))
                return (DtmParameters)DTMX13RNS1S2.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X14RNT1T2)))
                return (DtmParameters)DTMX14RNT1T2.DeepCopy();
            // x2
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X21RNS1R2)))
                return (DtmParameters)DTMX21RNS1R2.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X22RNR1R2)))
                return (DtmParameters)DTMX22RNR1R2.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X23RNS1S2)))
                return (DtmParameters)DTMX23RNS1S2.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X24RNT1T2)))
                return (DtmParameters)DTMX24RNT1T2.DeepCopy();
            // x3
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X31RNS1R1)))
                return (DtmParameters)DTMX31RNS1R1.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X32RNR1R1)))
                return (DtmParameters)DTMX32RNR1R1.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X33RNS1S1)))
                return (DtmParameters)DTMX33RNS1S1.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X34RNT1T1)))
                return (DtmParameters)DTMX34RNT1T1.DeepCopy();
            // x4
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X41RNS1R1)))
                return (DtmParameters)DTMX41RNS1R1.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X42RNR1R1)))
                return (DtmParameters)DTMX42RNR1R1.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X43RNS1S1)))
                return (DtmParameters)DTMX43RNS1S1.DeepCopy();
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X44RNT1T1)))
                return (DtmParameters)DTMX44RNT1T1.DeepCopy();
            else
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId does not identify a valid param set!", new ArgumentException());
        }

        /// <summary>
        /// Retrieve a DtmParameters by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>A populated DtmParameters parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static DtmParameters FromName(DtmParamNames Name)
        {
            switch (Name)
            {
                // x1
                case DtmParamNames.X11RNS1R2:
                    return (DtmParameters)DTMX11RNS1R2.DeepCopy();
                case DtmParamNames.X12RNR1R2:
                    return (DtmParameters)DTMX12RNR1R2.DeepCopy();
                case DtmParamNames.X13RNS1S2:
                    return (DtmParameters)DTMX13RNS1S2.DeepCopy();
                case DtmParamNames.X14RNT1T2:
                    return (DtmParameters)DTMX14RNT1T2.DeepCopy();
                // x2
                case DtmParamNames.X21RNS1R2:
                    return (DtmParameters)DTMX21RNS1R2.DeepCopy();
                case DtmParamNames.X22RNR1R2:
                    return (DtmParameters)DTMX22RNR1R2.DeepCopy();
                case DtmParamNames.X23RNS1S2:
                    return (DtmParameters)DTMX23RNS1S2.DeepCopy();
                case DtmParamNames.X24RNT1T2:
                    return (DtmParameters)DTMX24RNT1T2.DeepCopy();
                // x3
                case DtmParamNames.X31RNS1R1:
                    return (DtmParameters)DTMX31RNS1R1.DeepCopy();
                case DtmParamNames.X32RNR1R1:
                    return (DtmParameters)DTMX32RNR1R1.DeepCopy();
                case DtmParamNames.X33RNS1S1:
                    return (DtmParameters)DTMX33RNS1S1.DeepCopy();
                case DtmParamNames.X34RNT1T1:
                    return (DtmParameters)DTMX34RNT1T1.DeepCopy();
                // x4
                case DtmParamNames.X41RNS1R1:
                    return (DtmParameters)DTMX41RNS1R1.DeepCopy();
                case DtmParamNames.X42RNR1R1:
                    return (DtmParameters)DTMX42RNR1R1.DeepCopy();
                case DtmParamNames.X43RNS1S1:
                    return (DtmParameters)DTMX43RNS1S1.DeepCopy();
                case DtmParamNames.X44RNT1T1:
                    return (DtmParameters)DTMX44RNT1T1.DeepCopy();
                default:
                    throw new CryptoAsymmetricException("DtmParamSets:FromName", "The enumeration name is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Returns the security classification prefix
        /// </summary>
        /// 
        /// <param name="OId">A DtmParameters OId</param>
        /// 
        /// <returns>The security classification prefix</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static SecurityContexts GetContext(byte[] OId)
        {
            // x1
            if (Compare.IsEqual(OId, GetID(DtmParamNames.X11RNS1R2)) || Compare.IsEqual(OId, GetID(DtmParamNames.X12RNR1R2)) ||
                Compare.IsEqual(OId, GetID(DtmParamNames.X13RNS1S2)) || Compare.IsEqual(OId, GetID(DtmParamNames.X14RNT1T2)))
                return SecurityContexts.X1;
            // x2
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X21RNS1R2)) || Compare.IsEqual(OId, GetID(DtmParamNames.X22RNR1R2)) ||
                Compare.IsEqual(OId, GetID(DtmParamNames.X23RNS1S2)) || Compare.IsEqual(OId, GetID(DtmParamNames.X24RNT1T2)))
                return SecurityContexts.X2;
            // x3
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X31RNS1R1)) || Compare.IsEqual(OId, GetID(DtmParamNames.X32RNR1R1)) ||
                Compare.IsEqual(OId, GetID(DtmParamNames.X33RNS1S1)) || Compare.IsEqual(OId, GetID(DtmParamNames.X34RNT1T1)))
                return SecurityContexts.X3;
            // x4
            else if (Compare.IsEqual(OId, GetID(DtmParamNames.X41RNS1R1)) || Compare.IsEqual(OId, GetID(DtmParamNames.X42RNR1R1)) ||
                Compare.IsEqual(OId, GetID(DtmParamNames.X43RNS1S1)) || Compare.IsEqual(OId, GetID(DtmParamNames.X44RNT1T1)))
                return SecurityContexts.X4;
            else
                throw new CryptoAsymmetricException("DtmParamSets:GetContext", "The OId is unknown!", new ArgumentException());
        }

        /// <summary>
        /// Returns the security classification prefix
        /// </summary>
        /// 
        /// <param name="Name">The DtmParameters enumeration name</param>
        /// 
        /// <returns>The security classification prefix</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static SecurityContexts GetContext(DtmParamNames Name)
        {
            switch (Name)
            {
                // x1
                case DtmParamNames.X11RNS1R2:
                case DtmParamNames.X12RNR1R2:
                case DtmParamNames.X13RNS1S2:
                case DtmParamNames.X14RNT1T2:
                    return SecurityContexts.X1;
                // x2
                case DtmParamNames.X21RNS1R2:
                case DtmParamNames.X22RNR1R2:
                case DtmParamNames.X23RNS1S2:
                case DtmParamNames.X24RNT1T2:
                    return SecurityContexts.X2;
                // x3
                case DtmParamNames.X31RNS1R1:
                case DtmParamNames.X32RNR1R1:
                case DtmParamNames.X33RNS1S1:
                case DtmParamNames.X34RNT1T1:
                    return SecurityContexts.X3;
                // x4
                case DtmParamNames.X41RNS1R1:
                case DtmParamNames.X42RNR1R1:
                case DtmParamNames.X43RNS1S1:
                case DtmParamNames.X44RNT1T1:
                    return SecurityContexts.X4;
                default:
                    throw new CryptoAsymmetricException("DtmParamSets:GetContext", "The enumeration name is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Retrieve the DtmParameters OId by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>The 16 byte DtmParameters OId field</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static byte[] GetID(DtmParamNames Name)
        {
            switch (Name)
            {
                // x1
                case DtmParamNames.X11RNS1R2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.Skein256, (byte)BlockCiphers.Rijndael, (byte)Digests.Skein512, 1, 1, 0, 0 });
                case DtmParamNames.X12RNR1R2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.Rijndael, (byte)Digests.Skein256, (byte)BlockCiphers.Rijndael, (byte)Digests.Skein512, 1, 2, 0, 0 });
                case DtmParamNames.X13RNS1S2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.Skein256, (byte)BlockCiphers.Serpent, (byte)Digests.Skein512, 1, 3, 0, 0 });
                case DtmParamNames.X14RNT1T2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.Twofish, (byte)Digests.Skein256, (byte)BlockCiphers.Twofish, (byte)Digests.Skein512, 1, 4, 0, 0 });
                // x2
                case DtmParamNames.X21RNS1R2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1499EP1),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.None, (byte)BlockCiphers.Rijndael, (byte)Digests.Skein512, 2, 1, 0, 0 });
                case DtmParamNames.X22RNR1R2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1499EP1),
                        new byte[] { (byte)BlockCiphers.Rijndael, (byte)Digests.None, (byte)BlockCiphers.Rijndael, (byte)Digests.Skein512, 2, 2, 0, 0 });
                case DtmParamNames.X23RNS1S2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1499EP1),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.None, (byte)BlockCiphers.Serpent, (byte)Digests.Skein512, 2, 3, 0, 0 });
                case DtmParamNames.X24RNT1T2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1499EP1),
                        new byte[] { (byte)BlockCiphers.Twofish, (byte)Digests.None, (byte)BlockCiphers.Twofish, (byte)Digests.Skein512, 2, 4, 0, 0 });
                // x3
                case DtmParamNames.X31RNS1R1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1087EP2),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.None, (byte)BlockCiphers.Rijndael, (byte)Digests.None, 3, 1, 0, 0 });
                case DtmParamNames.X32RNR1R1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1087EP2),
                        new byte[] { (byte)BlockCiphers.Rijndael, (byte)Digests.None, (byte)BlockCiphers.Rijndael, (byte)Digests.None, 3, 2, 0, 0 });
                case DtmParamNames.X33RNS1S1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1087EP2),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.None, (byte)BlockCiphers.Serpent, (byte)Digests.None, 3, 3, 0, 0 });
                case DtmParamNames.X34RNT1T1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FE1087EP2),
                        new byte[] { (byte)BlockCiphers.Twofish, (byte)Digests.None, (byte)BlockCiphers.Twofish, (byte)Digests.None, 3, 4, 0, 0 });
                // x4
                case DtmParamNames.X41RNS1R1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.None, (byte)BlockCiphers.Rijndael, (byte)Digests.None, 4, 1, 0, 0 });
                case DtmParamNames.X42RNR1R1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
                        new byte[] { (byte)BlockCiphers.Rijndael, (byte)Digests.None, (byte)BlockCiphers.Rijndael, (byte)Digests.None, 4, 2, 0, 0 });
                case DtmParamNames.X43RNS1S1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
                        new byte[] { (byte)BlockCiphers.Serpent, (byte)Digests.None, (byte)BlockCiphers.Serpent, (byte)Digests.None, 4, 3, 0, 0 });
                case DtmParamNames.X44RNT1T1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
                        new byte[] { (byte)BlockCiphers.Twofish, (byte)Digests.None, (byte)BlockCiphers.Twofish, (byte)Digests.None, 4, 4, 0, 0 });
                default:
                    throw new CryptoAsymmetricException("DtmParamSets:GetID", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }
        #endregion

        #region Parameter Sets
        /* Note: Param naming Convention 
           Security Class 'X' followed by optimization type and sub class: 1 or 2 is best security, 3 is security and speed, 4 is best speed
           convention: first letter of asymmetric cipher and set/subset for both ciphers, then both symmetric ciphers first letter and type (1 for standard, 2 for extended) */

        #region X1
        /// <summary>
        /// Class 1, X1.1 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 powered Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX11RNS1R2 = new DtmParameters(
            // the 16 byte idetifier field containing a description of the cipher (see class notes)
            GetID(DtmParamNames.X11RNS1R2),
            // the auth-stage asymmetric ciphers parameter oid (can also be a serialized parameter)
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            // the primary-stage asymmetric ciphers parameter oid
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.CX1931, 0.2),
            // the auth-stage symmetric ciphers description
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32, Digests.Skein256),
            // the primary-stage symmetric ciphers description
            new DtmSessionStruct(BlockCiphers.Rijndael, 64, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            // the random generator used to pad messages
            Prngs.CSPPrng,
            // the maximum number of random bytes appended to a public key (actual number of bytes is chosen at random)
            1000,
            // the maximum number of random bytes prepended to a public key
            1000,
            // the maximum number of random bytes appended to the primary auth exchange (including asymmetric parameters)
            200,
            // the maximum number of random bytes prepended to the primary auth exchange
            200,
            // the maximum number of random bytes appended to the primary symmetric key exchange
            200,
            // the maximum number of random bytes prepended to the primary symmetric key exchange
            200,
            // the maximum number of random bytes appended to each post-exchange message (apply message append/prepend to hide the message type)
            0,
            // the maximum number of random bytes prepended to each post-exchange message
            0,
            // the maximum delay time before transmitting the primary public key (actual time is a random number of milliseconds up to this value)
            200,
            // the maximum delay time before transmitting the symmetric key
            10,
            // the maximum delay time before transmitting a message
            0);

        /// <summary>
        /// Class 1, X1.2 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael (AES256).
        /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 powered Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX12RNR1R2 = new DtmParameters(
            GetID(DtmParamNames.X12RNR1R2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.CX1931, 0.2),
            new DtmSessionStruct(BlockCiphers.Rijndael, 32, IVSizes.V128, RoundCounts.R14, Digests.Skein256),
            new DtmSessionStruct(BlockCiphers.Rijndael, 64, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        /// <summary>
        /// Class 1, X1.3 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 40 rounds of SHX with the Skein-512 powered Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX13RNS1S2 = new DtmParameters(
            GetID(DtmParamNames.X13RNS1S2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.CX1931, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Serpent, 64, IVSizes.V128, RoundCounts.R40, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        /// <summary>
        /// Class 1, X1.4 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
        /// Primary Stage: NTRU and 20 rounds of THX with the Skein-512 powered Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX14RNT1T2 = new DtmParameters(
            GetID(DtmParamNames.X14RNT1T2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.CX1931, 0.2),
            new DtmSessionStruct(BlockCiphers.Twofish, 32, IVSizes.V128, RoundCounts.R16),
            new DtmSessionStruct(BlockCiphers.Twofish, 64, IVSizes.V128, RoundCounts.R20, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);
        #endregion

        #region X2
        /// <summary>
        /// Class 2, X2.1 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX21RNS1R2 = new DtmParameters(
            GetID(DtmParamNames.X21RNS1R2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1499EP1, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Rijndael, 64, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        /// <summary>
        /// Class 2, X2.2 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael (AES256).
        /// Primary Stage: NTRU and 22 rounds of RHX with the Skein-512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX22RNR1R2 = new DtmParameters(
            GetID(DtmParamNames.X22RNR1R2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1499EP1, 0.2),
            new DtmSessionStruct(BlockCiphers.Rijndael, 32, IVSizes.V128, RoundCounts.R14),
            new DtmSessionStruct(BlockCiphers.Rijndael, 64, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        /// <summary>
        /// Class 2, X2.3 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 40 rounds of SHX with the Skein-512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX23RNS1S2 = new DtmParameters(
            GetID(DtmParamNames.X23RNS1S2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1499EP1, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Serpent, 64, IVSizes.V128, RoundCounts.R40, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        /// <summary>
        /// Class 2, X2.4 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
        /// Primary Stage: NTRU and 20 rounds of THX with the Skein-512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX24RNT1T2 = new DtmParameters(
            GetID(DtmParamNames.X24RNT1T2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1499EP1, 0.2),
            new DtmSessionStruct(BlockCiphers.Twofish, 32, IVSizes.V128, RoundCounts.R16),
            new DtmSessionStruct(BlockCiphers.Twofish, 64, IVSizes.V128, RoundCounts.R20, Digests.Skein512),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);
        #endregion

        #region X3
        /// <summary>
        /// Class 3, X3.1 Configuration: Optimized for security and speed.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent with a 256 bit key.
        /// Primary Stage: NTRU and 22 rounds of Rijndael with a 512 bit key.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX31RNS1R1 = new DtmParameters(
            GetID(DtmParamNames.X31RNS1R1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1087EP2, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Rijndael, 64, IVSizes.V128, RoundCounts.R22),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);

        /// <summary>
        /// Class 3, X3.2 Configuration: Optimized for security and speed.
        /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael with a 256 bit key (AES256).
        /// Primary Stage: NTRU and 22 rounds of Rijndael with a 512 bit key.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX32RNR1R1 = new DtmParameters(
            GetID(DtmParamNames.X32RNR1R1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1087EP2, 0.2),
            new DtmSessionStruct(BlockCiphers.Rijndael, 32, IVSizes.V128, RoundCounts.R14),
            new DtmSessionStruct(BlockCiphers.Rijndael, 64, IVSizes.V128, RoundCounts.R22),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);

        /// <summary>
        /// Class 3, X3.3 Configuration: Optimized for security and speed.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent with a 256 bit key.
        /// Primary Stage: NTRU and 32 rounds of Serpent with a 512 bit key.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX33RNS1S1 = new DtmParameters(
            GetID(DtmParamNames.X33RNS1S1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1087EP2, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Serpent, 64, IVSizes.V128, RoundCounts.R32),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);

        /// <summary>
        /// Class 3, X3.4 Configuration: Optimized for security and speed.
        /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish with a 256 bit key.
        /// Primary Stage: NTRU and 20 rounds of Twofish with a 512 bit key.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX34RNT1T1 = new DtmParameters(
            GetID(DtmParamNames.X34RNT1T1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FE1087EP2, 0.2),
            new DtmSessionStruct(BlockCiphers.Twofish, 32, IVSizes.V128, RoundCounts.R16),
            new DtmSessionStruct(BlockCiphers.Twofish, 64, IVSizes.V128, RoundCounts.R20),
            Prngs.CSPPrng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);
        #endregion

        #region X4
        /// <summary>
        /// Class 4, X4.1 Configuration: Optimized for speed.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 14 rounds of Rijndael (AES256).</para>
        /// </summary>
        public static readonly DtmParameters DTMX41RNS1R1 = new DtmParameters(
            GetID(DtmParamNames.X41RNS1R1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FA2011743, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Rijndael, 32, IVSizes.V128, RoundCounts.R14),
            Prngs.CSPPrng);

        /// <summary>
        /// Class 4, X4.2 Configuration: Optimized for speed.
        /// <para>Authentication Stage: Ring-LWE and 14 rounds of Rijndael (AES256).
        /// Primary Stage: NTRU and 14 rounds of Rijndael (AES256).</para>
        /// </summary>
        public static readonly DtmParameters DTMX42RNR1R1 = new DtmParameters(
            GetID(DtmParamNames.X42RNR1R1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FA2011743, 0.2),
            new DtmSessionStruct(BlockCiphers.Rijndael, 32, IVSizes.V128, RoundCounts.R14),
            new DtmSessionStruct(BlockCiphers.Rijndael, 32, IVSizes.V128, RoundCounts.R14),
            Prngs.CSPPrng);

        /// <summary>
        /// Class 4, X4.3 Configuration: Optimized for speed.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 32 rounds of Serpent.</para>
        /// </summary>
        public static readonly DtmParameters DTMX43RNS1S1 = new DtmParameters(
            GetID(DtmParamNames.X43RNS1S1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FA2011743, 0.2),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSessionStruct(BlockCiphers.Serpent, 32, IVSizes.V128, RoundCounts.R32),
            Prngs.CSPPrng);

        /// <summary>
        /// Class 4, X4.4 Configuration: Optimized for speed.
        /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
        /// Primary Stage: NTRU and 16 rounds of Twofish.</para>
        /// </summary>
        public static readonly DtmParameters DTMX44RNT1T1 = new DtmParameters(
            GetID(DtmParamNames.X44RNT1T1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetFormatted(NTRUParamSets.NTRUParamNames.FA2011743, 0.2),
            new DtmSessionStruct(BlockCiphers.Twofish, 32, IVSizes.V128, RoundCounts.R16),
            new DtmSessionStruct(BlockCiphers.Twofish, 32, IVSizes.V128, RoundCounts.R16),
            Prngs.CSPPrng);
        #endregion
        #endregion
    }
}
