#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

#region License Information
// NTRU Encrypt in C# (NTRUSharp)
// Copyright (C) 2015 John Underhill
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
//
// Based on the java project NTRUEncrypt by Tim Buktu: <https://github.com/tbuktu/ntru> and the C version
// <https://github.com/NTRUOpenSourceProject/ntru-crypto> NTRUOpenSourceProject/ntru-crypto.
// NTRU is owned and patented by Security Innovations: <https://www.securityinnovation.com/products/encryption-libraries/ntru-crypto/>,
// authors and originators include; Jeffrey Hoffstein, Jill Pipher, and Joseph H. Silverman.
// 
// Implementation Details:
// An implementation of NTRU Encrypt in C#.
// Written by John Underhill, April 09, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU
{
  /// <summary>
  /// A set of pre-defined EES encryption parameter sets 
  /// based on <see href="https://github.com/tbuktu/ntru/blob/master/src/main/java/net/sf/ntru/encrypt/EncryptionParameters.java">EncryptionParameters.java</see>.
  /// <para>Note: Sets names starting with 'A' (ex. A2011439), are the recommended sets from the original author (T. Buktu). Sets pre-fixed with 'F' (ex. FE1087EP2) are the fast polynomial versions. 
  /// Sets prefixed with 'CX' (ex. CX1931) are experimental, they use larger N, df, and dm values, and a 512 bit digest for the IGF and mask.</para>
  /// </summary>
  /// 
  /// <remarks>
  /// <description><h4>Parameter OId:</h4></description>
  /// <list type="bullet">
  /// <item><description>A Parameter Set OId (uniquely identifies the parameter set), is always the first four bytes of a serialized parameter set.</description></item>
  /// <item><description>The OId format is ordered as: <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Unique</c>.</description></item>
  /// <item><description>An NTRU parameters <c>Family</c> designator (first byte) is always the value <c>2</c>, and corresponds to its entry in the <see cref="AsymmetricEngines"/> enumeration.</description></item>
  /// <item><description>The second byte: <c>Set</c>, defines the parameter origin: ESS is the value <c>1</c>, APR is <c>2</c>, and CEX is <c>3</c>.</description></item>
  /// <item><description>The third byte: <c>SubSet</c>, defines the PolyType; simple <c>1</c> or product form <c>2</c>.</description></item>
  /// <item><description>The fourth byte can be a unique designator.</description></item>
  /// </list>
  /// </remarks>
  public static class NTRUParamSets
  {
    #region Enums
    /// <summary>
    /// EES set id's for common parameter values
    /// </summary>
    public enum NTRUParamNames : int
    {
      /// <summary>
      /// Experimental, use with caution. Uses a larger ring and Skein512.
      /// <para>MaxText: 233, N:1931 Q:2048, Df:380, PublicKey Size: 2660, PrivateKey Size: 388</para>
      /// </summary>
      CX1931,
      /// <summary>
      /// Experimental, use with caution. Uses a larger ring and Skein512.
      /// <para>MaxText: 219, N:1861 Q:2048, Df:290, PublicKey Size: 2563, PrivateKey Size: 374</para>
      /// </summary>
      CX1861,
      /// <summary>
      /// A conservative parameter set that gives 256 bits of security and is optimized for key size.
      /// <para>MaxText: 170, N:1087 Q:2048, Df:120, PublicKey Size: 1499, PrivateKey Size: 221</para>
      /// </summary>
      E1087EP2,
      /// <summary>
      /// A conservative parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
      /// <para>MaxText: 186, N:1171 Q:2048, Df:106, PublicKey Size: 1615, PrivateKey Size: 237</para>
      /// </summary>
      E1171EP1,
      /// <summary>
      /// A conservative parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
      /// <para>MaxText: 248, N:1499 Q:2048, Df:79, PublicKey Size: 2066, PrivateKey Size: 302</para>
      /// </summary>
      E1499EP1,
      /// <summary>
      /// A parameter set that gives 128 bits of security and uses simple ternary polynomials.
      /// <para>MaxText: 65, N:439 Q:2048, Df:146, PublicKey Size: 608, PrivateKey Size: 92</para>
      /// </summary>
      A2011439,
      /// <summary>
      /// A parameter set that gives 256 bits of security and uses simple ternary polynomials.
      /// <para>MaxText: 106, N:743 Q:2048, Df:248, PublicKey Size: 1026, PrivateKey Size: 153</para>
      /// </summary>
      A2011743,
      /// <summary>
      /// A product-form version of <c>EES1087EP2</c>
      /// <para>MaxText: 170, N:1087 Q:2048, Df:120, PublicKey Size: 1499, PrivateKey Size: 93</para>
      /// </summary>
      FE1087EP2,
      /// <summary>
      /// A product-form version of <c>EES1171EP1</c>
      /// <para>MaxText: 186, N:1171 Q:2048, Df:106, PublicKey Size: 1615, PrivateKey Size: 237</para>
      /// </summary>
      FE1171EP1,
      /// <summary>
      /// A product-form version of <c>EES1499EP1</c>
      /// <para>MaxText: 248, N:1499 Q:2048, Df:79, PublicKey Size: 2066, PrivateKey Size: 302</para>
      /// </summary>
      FE1499EP1,
      /// <summary>
      /// Like <c>APR2011743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
      /// <para>MaxText: 106, N:743 Q:2048, Df:248, PublicKey Size: 1026, PrivateKey Size: 123</para>
      /// </summary>
      FA2011743,
      /// <summary>
      /// Like <c>APR2011_439</c>, this parameter set gives 128 bits of security but uses product-form polynomials and <c>f=1+pF</c>.
      /// <para>MaxText: 65, N:439 Q:2048, Df:146, PublicKey Size: 608, PrivateKey Size: 79</para>
      /// </summary>
      FA2011439,
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Retrieve a parameter set by its identity code
    /// </summary>
    /// 
    /// <param name="OId">The 4 byte parameter set identity code</param>
    /// 
    /// <returns>A parameter set</returns>
    /// 
    /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is used</exception>
    public static NTRUParameters FromId(byte[] OId)
    {
      if (OId == null)
        throw new CryptoAsymmetricException("NTRUParameters:FromId", "OId can not be null!", new ArgumentNullException());
      if (OId.Length != 4)
        throw new CryptoAsymmetricException("NTRUParameters:FromId", "OId must be 4 bytes in length!", new ArgumentOutOfRangeException());
      if (OId[0] != 2)
        throw new CryptoAsymmetricException("NTRUParameters:FromId", "OId is not a valid NTRU parameter id!", new ArgumentException());

      if (OId[2] == 2)
      {
        if (OId[3] == 63)
          return (NTRUParameters)EES1087EP2FAST.DeepCopy();
        else if (OId[3] == 64)
          return (NTRUParameters)EES1171EP1FAST.DeepCopy();
        else if (OId[3] == 65)
          return (NTRUParameters)EES1499EP1FAST.DeepCopy();
        else if (OId[3] == 101)
          return (NTRUParameters)APR2011439FAST.DeepCopy();
        else if (OId[3] == 105)
          return (NTRUParameters)APR2011743FAST.DeepCopy();
      }
      else if (OId[2] == 1)
      {
        if (OId[3] == 63)
          return (NTRUParameters)EES1087EP2.DeepCopy();
        else if (OId[3] == 64)
          return (NTRUParameters)EES1171EP1.DeepCopy();
        else if (OId[3] == 65)
          return (NTRUParameters)EES1499EP1.DeepCopy();
        else if (OId[3] == 101)
          return (NTRUParameters)APR2011439.DeepCopy();
        else if (OId[3] == 105)
          return (NTRUParameters)APR2011743.DeepCopy();
        else if (OId[3] == 7)
          return (NTRUParameters)CX1861SK512.DeepCopy();
        else if (OId[3] == 8)
          return (NTRUParameters)CX1931SK512.DeepCopy();
      }

      throw new CryptoAsymmetricException("NTRUParameters:FromId", "OId does not identify a valid param set!", new ArgumentException());
    }

    /// <summary>
    /// Retrieve a parameter set by its enumeration name
    /// </summary>
    /// 
    /// <param name="Name">The enumeration name</param>
    /// 
    /// <returns>A populated parameter set</returns>
    /// 
    /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is used</exception>
    public static NTRUParameters FromName(NTRUParamNames Name)
    {
      switch (Name)
      {
        case NTRUParamNames.A2011439:
          return (NTRUParameters)APR2011439.DeepCopy();
        case NTRUParamNames.A2011743:
          return (NTRUParameters)APR2011743.DeepCopy();
        case NTRUParamNames.E1087EP2:
          return (NTRUParameters)EES1087EP2.DeepCopy();
        case NTRUParamNames.E1171EP1:
          return (NTRUParameters)EES1171EP1.DeepCopy();
        case NTRUParamNames.E1499EP1:
          return (NTRUParameters)EES1499EP1.DeepCopy();
        case NTRUParamNames.FA2011439:
          return (NTRUParameters)APR2011439FAST.DeepCopy();
        case NTRUParamNames.FA2011743:
          return (NTRUParameters)APR2011743FAST.DeepCopy();
        case NTRUParamNames.FE1087EP2:
          return (NTRUParameters)EES1087EP2FAST.DeepCopy();
        case NTRUParamNames.FE1171EP1:
          return (NTRUParameters)EES1171EP1FAST.DeepCopy();
        case NTRUParamNames.FE1499EP1:
          return (NTRUParameters)EES1499EP1FAST.DeepCopy();
        case NTRUParamNames.CX1861:
          return (NTRUParameters)CX1861SK512.DeepCopy();
        case NTRUParamNames.CX1931:
          return (NTRUParameters)CX1931SK512.DeepCopy();
        default:
          throw new CryptoAsymmetricException("NTRUParameters:FromName", "The enumeration name is unknown!", new ArgumentException());
      }
    }

    /// <summary>
    /// Retrieve the OId for a parameter set
    /// </summary>
    /// 
    /// <param name="Name">The enumeration name</param>
    /// 
    /// <returns>The parameters 4 byte OId</returns>
    /// 
    /// <exception cref="CryptoAsymmetricException">Thrown if an invalid name is used</exception>
    public static byte[] GetID(NTRUParamNames Name)
    {
      switch (Name)
      {
        case NTRUParamNames.A2011439:
          return new byte[] { 2, 2, 1, 101 };
        case NTRUParamNames.A2011743:
          return new byte[] { 2, 2, 1, 105 };
        case NTRUParamNames.E1087EP2:
          return new byte[] { 2, 1, 1, 63 };
        case NTRUParamNames.E1171EP1:
          return new byte[] { 2, 1, 1, 64 };
        case NTRUParamNames.E1499EP1:
          return new byte[] { 2, 1, 1, 65 };
        case NTRUParamNames.FA2011439:
          return new byte[] { 2, 2, 2, 101 };
        case NTRUParamNames.FA2011743:
          return new byte[] { 2, 2, 2, 105 };
        case NTRUParamNames.FE1087EP2:
          return new byte[] { 2, 1, 2, 63 };
        case NTRUParamNames.FE1171EP1:
          return new byte[] { 2, 1, 2, 64 };
        case NTRUParamNames.FE1499EP1:
          return new byte[] { 2, 1, 2, 65 };
        case NTRUParamNames.CX1861:
          return new byte[] { 2, 3, 1, 7 };
        case NTRUParamNames.CX1931:
          return new byte[] { 2, 3, 1, 8 };
        default:
          throw new CryptoAsymmetricException("NTRUParameters:FromName", "The enumeration name is unknown!", new ArgumentException());
      }
    }
    #endregion

    #region Parameter Sets
    // Note: max message size is calculation of N and Db; (N*3/2/8 - Length-Db/8). Max bytes: EES1087EP2:170, EES1171EP1:186, EES1499EP1:248, APR2011439:65, APR2011743:106
    // >OId is 4 bytes Family:Set:SubSet:Unique

    /// <summary>
    /// Experimental, use with caution. Uses a larger ring and Skein512.
    /// <para>MaxText: 233, N:1931 Q:2048, Df:380, PublicKey Size: 2660, PrivateKey Size: 388</para>
    /// </summary>
    public static readonly NTRUParameters CX1931SK512 = new NTRUParameters(new byte[] { 2, 3, 1, 8 }, 1931, 2048, 380, 380, 0, 1024, 20, 30, 11, true, true, false, Digests.Skein512, Prngs.CTRPrng);
    /// <summary>
    /// Experimental, use with caution. Uses a larger ring and Skein512.
    /// <para>MaxText: 219, N:1861 Q:2048, Df:290, PublicKey Size: 2563, PrivateKey Size: 374</para>
    /// </summary>
    public static readonly NTRUParameters CX1861SK512 = new NTRUParameters(new byte[] { 2, 3, 1, 7 }, 1861, 2048, 290, 290, 0, 1024, 14, 22, 10, true, true, false, Digests.Skein512, Prngs.CTRPrng);
    /// <summary>
    /// A conservative parameter set that gives 256 bits of security and is optimized for key size.
    /// <para>MaxText: 170, N:1087 Q:2048, Df:120, PublicKey Size: 1499, PrivateKey Size: 221</para>
    /// </summary>
    public static readonly NTRUParameters EES1087EP2 = new NTRUParameters(new byte[] { 2, 1, 1, 63 }, 1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, true, false, Digests.SHA512, Prngs.CTRPrng);
    /// <summary>
    /// A product-form version of <c>EES1087EP2</c>
    /// <para>MaxText: 170, N:1087 Q:2048, Df:120, PublicKey Size: 1499, PrivateKey Size: 93</para>
    /// </summary>
    public static readonly NTRUParameters EES1087EP2FAST = new NTRUParameters(new byte[] { 2, 1, 2, 63 }, 1087, 2048, 8, 8, 11, 120, 0, 256, 13, 25, 14, true, true, true, Digests.SHA512, Prngs.CTRPrng);
    /// <summary>
    /// A conservative parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
    /// <para>MaxText: 186, N:1171 Q:2048, Df:106, PublicKey Size: 1615, PrivateKey Size: 237</para>
    /// </summary>
    public static readonly NTRUParameters EES1171EP1 = new NTRUParameters(new byte[] { 2, 1, 1, 64 }, 1171, 2048, 106, 106, 0, 256, 13, 20, 15, true, true, false, Digests.SHA512, Prngs.CTRPrng);
    /// <summary>
    /// A product-form version of <c>EES1171EP1</c>
    /// <para>MaxText: 186, N:1171 Q:2048, Df:106, PublicKey Size: 1615, PrivateKey Size: 237</para>
    /// </summary>
    public static readonly NTRUParameters EES1171EP1FAST = new NTRUParameters(new byte[] { 2, 1, 2, 64 }, 1171, 2048, 8, 7, 11, 106, 0, 256, 13, 20, 15, true, true, true, Digests.SHA512, Prngs.CTRPrng);
    
    /// <summary>
    /// A product-form version of <c>EES1499EP1</c>
    /// <para>MaxText: 248, N:1499 Q:2048, Df:79, PublicKey Size: 2066, PrivateKey Size: 302</para>
    /// </summary>
    public static readonly NTRUParameters EES1499EP1FAST = new NTRUParameters(new byte[] { 2, 1, 2, 65 }, 1499, 2048, 7, 6, 11, 79, 0, 256, 13, 17, 19, true, true, true, Digests.SHA512, Prngs.CTRPrng);
    /// <summary>
    /// A conservative parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
    /// <para>MaxText: 248, N:1499 Q:2048, Df:79, PublicKey Size: 2066, PrivateKey Size: 302</para>
    /// </summary>
    public static readonly NTRUParameters EES1499EP1 = new NTRUParameters(new byte[] { 2, 1, 1, 65 }, 1499, 2048, 79, 79, 0, 256, 13, 17, 19, true, true, false, Digests.SHA512, Prngs.CTRPrng);

    /// <summary>
    /// Not sure this implementation is correct!!!! EES743EPS uses uses product-form polynomials
    /// https://github.com/tbuktu/libntru/blob/master/src/encparams.c
    /// https://eprint.iacr.org/2015/708.pdf
    /// dg = N/3 = 247
    /// </summary>
    public static readonly NTRUParameters EES743EP1 = new NTRUParameters(new byte[] { 2, 2, 2, 106 }, 743, 2048, 11, 11, 15, 204, 106, 256, 13, 12, 7, true, false, true, Digests.SHA256, Prngs.CTRPrng);

    /// <summary>
    /// A parameter set that gives 256 bits of security and uses simple ternary polynomials.
    /// <para>MaxText: 106, N:743 Q:2048, Df:248, PublicKey Size: 1026, PrivateKey Size: 153</para>
    /// </summary>
    public static readonly NTRUParameters APR2011743 = new NTRUParameters(new byte[] { 2, 2, 1, 105 }, 743, 2048, 248, 220, 60, 256, 12, 27, 14, true, false, false, Digests.SHA512, Prngs.CTRPrng);
    /// <summary>
    /// Like <c>APR2011_743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
    /// <para>MaxText: 106, N:743 Q:2048, Df:248, PublicKey Size: 1026, PrivateKey Size: 123</para>
    /// </summary>
    public static readonly NTRUParameters APR2011743FAST = new NTRUParameters(new byte[] { 2, 2, 2, 105 }, 743, 2048, 11, 11, 15, 220, 60, 256, 12, 27, 14, true, false, true, Digests.SHA512, Prngs.CTRPrng);
    /// <summary>
    /// A parameter set that gives 128 bits of security and uses simple ternary polynomials.
    /// <para>MaxText: 65, N:439 Q:2048, Df:146, PublicKey Size: 608, PrivateKey Size: 92</para>
    /// </summary>
    public static readonly NTRUParameters APR2011439 = new NTRUParameters(new byte[] { 2, 2, 1, 101 }, 439, 2048, 146, 130, 126, 128, 12, 32, 9, true, true, false, Digests.SHA256, Prngs.CTRPrng);
    /// <summary>
    /// Like <c>APR2011_439</c>, this parameter set gives 128 bits of security but uses product-form polynomials and <c>f=1+pF</c>.
    /// <para>MaxText: 65, N:439 Q:2048, Df:146, PublicKey Size: 608, PrivateKey Size: 79</para>
    /// </summary>
    public static readonly NTRUParameters APR2011439FAST = new NTRUParameters(new byte[] { 2, 2, 2, 101 }, 439, 2048, 9, 8, 5, 130, 126, 128, 12, 32, 9, true, true, true, Digests.SHA256, Prngs.CTRPrng);
    #endregion
  }
}