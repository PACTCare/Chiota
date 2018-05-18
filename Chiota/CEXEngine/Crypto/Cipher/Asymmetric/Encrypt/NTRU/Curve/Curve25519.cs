#region License Information
// NTRU Encrypt in C# (NTRUSharp)
// Copyright (C) 2015 John Underhill
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.E.  See the
// GNU General Public License for more details.
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

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Curve
{
    /// <summary>
    /// Generic 64-bit integer implementation of Curve25519 ECDH.
    /// <para>Written by Matthijs van Duin, 200608242056
    /// Based on work by Daniel J Bernstein; 
    /// A state of the art <a href="http://cr.yp.to/ecdh.html">Diffie-Hellman</a> function: 
    /// Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.
    /// Ported to C# by John Underhill, 14/03/15.
    /// Original: <a href="http://cds.xs4all.nl:8081/ecdh/">version</a>.</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <example>
    /// <description>DIGITAL SIGNATURES : Deterministic EC-KCDSA</description>
    /// <code>
    ///    s is the private key for signing
    ///    P is the corresponding internal key
    ///    Z is the context data (signer internal key or certificate, etc)
    /// </code>
    /// 
    /// <description>signing:</description>
    /// <code>
    ///    m = hash(Z, message)
    ///    x = hash(m, s)
    ///    keygen25519(Y, NULL, x);
    ///    r = hash(Y);
    ///    h = m XOR r
    ///    sign25519(v, h, x, s);
    ///
    ///    output (v,r) as the signature
    /// </code>
    /// 
    /// <description>verification:</description>
    /// <code>
    ///    m = hash(Z, message);
    ///    h = m XOR r
    ///    verify25519(Y, v, h, P)
    ///
    ///    confirm  r == hash(Y)
    /// </code>
    /// </example>
    /// 
    /// <para>It would seem to me that it would be simpler to have the signer directly do 
    /// h = hash(m, Y) and send that to the recipient instead of r, who can verify 
    /// the signature by checking h == hash(m, Y).  If there are any problems with 
    /// such a scheme, please let me know.</para>
    /// <para>Also, EC-KCDSA (like most DS algorithms) picks x random, which is a waste of 
    /// perfectly good entropy, but does allow Y to be calculated in advance of (or 
    /// parallel to) hashing the message.</para>
    /// </remarks>
    internal sealed class Curve25519
    {
        #region Constants
        // key size
        internal const int KEY_SIZE = 32;
        #endregion

        #region Fields
        // (1 << 25) - 1
        private static int P25 = 33554431;
        // (1 << 26) - 1
        private static int P26 = 67108863;
        // constants 2Gy and 1/(2Gy) 
        private static Long10 BASE_2Y = new Long10(39999547, 18689728, 59995525, 1648697, 57546132, 24010086, 19059592, 5425144, 63499247, 16420658);
        private static Long10 BASE_R2Y = new Long10(5744, 8160848, 4790893, 13779497, 35730846, 12541209, 49101323, 30047407, 40071253, 6226132);
        // smallest multiple of the order that's >= 2^255 
        private static byte[] ORDER_TIMES_8 = 
        {
		    104, 159, 174, 231, 210, 24,  147, 192,
		    178, 230, 188, 23, 245, 206, 247, 166,
		    0, 0, 0, 0, 0, 0, 0, 0,
		    0, 0, 0, 0, 0, 0, 0, 128
	    };
        // group order (a prime near 2^252+2^124)
        private static byte[] ORDER = 
        {
		    237, 211, 245, 92, 26,  99,  18,  88,
		    214, 156, 247, 162, 222, 249, 222, 20,
		    0, 0, 0, 0, 0, 0, 0, 0,
		    0, 0, 0, 0, 0, 0, 0, 16
	    };
        // the prime 2^255-19
        private static byte[] PRIME = 
        {
		    237, 255, 255, 255, 255, 255, 255, 255,
		    255, 255, 255, 255, 255, 255, 255, 255,
		    255, 255, 255, 255, 255, 255, 255, 255,
	        255, 255, 255, 255, 255, 255, 255, 127
	    };
        private static byte[] ZERO = 
        {
		    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	    };
        #endregion

        #region Public Methods
        /// <summary>
        /// Private key clamping
        /// </summary>
        /// 
        /// <param name="K">Private key for key agreement</param>
        internal static void Clamp(byte[] K)
        {
            K[31] &= 0x7F;
            K[31] |= 0x40;
            K[0] &= 0xF8;
        }

        /// <summary>
        /// Key-pair generation
        /// </summary>
        /// 
        /// <param name="P">Public key</param>
        /// <param name="S">Private key for signing</param>
        /// <param name="K">Private key for key agreement</param>
        /// 
        /// <remarks>if S is not NULL, this function has data-dependent timing</remarks>
        internal static void Keygen(byte[] P, byte[] S, byte[] K)
        {
            Clamp(K);
            Core(P, S, K, null);
        }

        /// <summary>
        /// Key agreement
        /// </summary>
        /// 
        /// <param name="Z">Shared secret (needs hashing before use)</param>
        /// <param name="K">Private key for key agreement</param>
        /// <param name="P">Peer's internal key</param>
        internal static void Curve(byte[] Z, byte[] K, byte[] P)
        {
            Core(Z, null, K, P);
        }

        /// <summary>
        /// Signature generation primitive, calculates (x-h)s mod q
        /// </summary>
        /// 
        /// <param name="V">Signature value</param>
        /// <param name="H">Signature hash (of message, signature pub key, and context data)</param>
        /// <param name="X">Signature private key</param>
        /// <param name="S">Private key for signing</param>
        /// 
        /// <returns>True on success, false on failure (use different x or h)</returns>
        internal static bool Sign(byte[] V, byte[] H, byte[] X, byte[] S)
        {
            // v = (x - h) s  mod q 
            byte[] tmp1 = new byte[65];
            byte[] tmp2 = new byte[33];
            int w;
            int i;

            for (i = 0; i < 32; i++)
                V[i] = 0;

            i = MulaSmall(V, X, 0, H, 32, -1);
            MulaSmall(V, V, 0, ORDER, 32, (15 - V[31]) / 16);
            Mula32(tmp1, V, S, 32, 1);
            DivMod(tmp2, tmp1, 64, ORDER, 32);

            for (w = 0, i = 0; i < 32; i++)
                w |= V[i] = tmp1[i];

            return w != 0;
        }

        /// <summary>
        /// Signature verification primitive, calculates Y = vP + hG
        /// </summary>
        /// 
        /// <param name="Y">Signature internal key</param>
        /// <param name="V">Signature value</param>
        /// <param name="H">Signature hash</param>
        /// <param name="P">Public key</param>
        internal static void Verify(byte[] Y, byte[] V, byte[] H, byte[] P)
        {
            // Y = v abs(P) + h G  */
            byte[] d = new byte[32];
            Long10[] p = new Long10[] { new Long10(), new Long10() }, s = new Long10[] { new Long10(), new Long10() }, yx = new Long10[] { new Long10(), new Long10(), new Long10() },
                yz = new Long10[] { new Long10(), new Long10(), new Long10() }, t1 = new Long10[] { new Long10(), new Long10(), new Long10() }, t2 = new Long10[] { new Long10(), new Long10(), new Long10() };

            int vi = 0, hi = 0, di = 0, nvh = 0, i, j, k;

            // set p[0] to G and p[1] to P
            Set(p[0], 9);
            Unpack(p[1], P);

            XtoY2(t1[0], t2[0], p[1]);	        // t2[0] = Py^2  
            Sqrt(t1[0], t2[0]);	                // t1[0] = Py or -Py  
            j = IsNegative(t1[0]);		        //      ... check which  
            t2[0].N0 += 39420360;		        // t2[0] = Py^2 + Gy^2  
            Mul(t2[1], BASE_2Y, t1[0]);         // t2[1] = 2 Py Gy or -2 Py Gy  
            Sub(t1[j], t2[0], t2[1]);	        // t1[0] = Py^2 + Gy^2 - 2 Py Gy  
            AddXY(t1[1 - j], t2[0], t2[1]);     // t1[1] = Py^2 + Gy^2 + 2 Py Gy  
            Copy(t2[0], p[1]);		            // t2[0] = Px  
            t2[0].N0 -= 9;			            // t2[0] = Px - Gx  
            Sqr(t2[1], t2[0]);		            // t2[1] = (Px - Gx)^2  
            Recip(t2[0], t2[1], 0);	            // t2[0] = 1/(Px - Gx)^2  
            Mul(s[0], t1[0], t2[0]);	        // s[0] = t1[0]/(Px - Gx)^2  
            Sub(s[0], s[0], p[1]);	            // s[0] = t1[0]/(Px - Gx)^2 - Px  
            s[0].N0 -= 9 + 486662;		        // s[0] = X(P+G)  
            Mul(s[1], t1[1], t2[0]);	        // s[1] = t1[1]/(Px - Gx)^2  
            Sub(s[1], s[1], p[1]);	            // s[1] = t1[1]/(Px - Gx)^2 - Px  
            s[1].N0 -= 9 + 486662;		        // s[1] = X(P-G)  
            MulSmall(s[0], s[0], 1);	        // reduce s[0] 
            MulSmall(s[1], s[1], 1);	        // reduce s[1] 


            // prepare the chain  
            for (i = 0; i < 32; i++)
            {
                vi = (vi >> 8) ^ (V[i] & 0xFF) ^ ((V[i] & 0xFF) << 1);
                hi = (hi >> 8) ^ (H[i] & 0xFF) ^ ((H[i] & 0xFF) << 1);
                nvh = ~(vi ^ hi);
                di = (nvh & (di & 0x80) >> 7) ^ vi;
                di ^= nvh & (di & 0x01) << 1;
                di ^= nvh & (di & 0x02) << 1;
                di ^= nvh & (di & 0x04) << 1;
                di ^= nvh & (di & 0x08) << 1;
                di ^= nvh & (di & 0x10) << 1;
                di ^= nvh & (di & 0x20) << 1;
                di ^= nvh & (di & 0x40) << 1;
                d[i] = (byte)di;
            }

            di = ((nvh & (di & 0x80) << 1) ^ vi) >> 8;

            // initialize state 
            Set(yx[0], 1);
            Copy(yx[1], p[di]);
            Copy(yx[2], s[0]);
            Set(yz[0], 0);
            Set(yz[1], 1);
            Set(yz[2], 1);

            // y[0] is (even)P + (even)G
            // y[1] is (even)P + (odd)G  if current d-bit is 0
            // y[1] is (odd)P + (even)G  if current d-bit is 1
            // y[2] is (odd)P + (odd)G

            vi = 0;
            hi = 0;

            // and go for it! 
            for (i = 32; i-- != 0; )
            {
                vi = (vi << 8) | (V[i] & 0xFF);
                hi = (hi << 8) | (H[i] & 0xFF);
                di = (di << 8) | (d[i] & 0xFF);

                for (j = 8; j-- != 0; )
                {
                    MontPrep(t1[0], t2[0], yx[0], yz[0]);
                    MontPrep(t1[1], t2[1], yx[1], yz[1]);
                    MontPrep(t1[2], t2[2], yx[2], yz[2]);

                    k = ((vi ^ vi >> 1) >> j & 1) + ((hi ^ hi >> 1) >> j & 1);
                    MontDbl(yx[2], yz[2], t1[k], t2[k], yx[0], yz[0]);

                    k = (di >> j & 2) ^ ((di >> j & 1) << 1);
                    MontAdd(t1[1], t2[1], t1[k], t2[k], yx[1], yz[1], p[di >> j & 1]);
                    MontAdd(t1[2], t2[2], t1[0], t2[0], yx[2], yz[2], s[((vi ^ hi) >> j & 2) >> 1]);
                }
            }

            k = (vi & 1) + (hi & 1);
            Recip(t1[0], yz[k], 0);
            Mul(t1[1], yx[k], t1[0]);

            Pack(t1[1], Y);
        }
        #endregion

        #region Long10 Class
        /// <remarks>
        /// Using this class instead of long[10] to avoid bounds checks.
        /// </remarks>
        private class Long10
        {
            internal Long10() { }

            internal Long10(long N0, long N1, long N2, long N3, long N4, long N5, long N6, long N7, long N8, long N9)
            {
                this.N0 = N0; this.N1 = N1; this.N2 = N2;
                this.N3 = N3; this.N4 = N4; this.N5 = N5;
                this.N6 = N6; this.N7 = N7; this.N8 = N8;
                this.N9 = N9;
            }

            internal long N0, N1, N2, N3, N4, N5, N6, N7, N8, N9;
        }
        #endregion

        #region Private Methods

        private static void Copy32(byte[] D, byte[] S)
        {
            for (int i = 0; i < 32; i++)
                D[i] = S[i];
        }

        /// <remarks>
        /// p[m..n+m-1] = q[m..n+m-1] + z * x, n is the size of x 
        /// n+m is the size of p and q
        /// </remarks>
        private static int MulaSmall(byte[] P, byte[] Q, int M, byte[] X, int N, int Z)
        {
            int v = 0;
            for (int i = 0; i < N; ++i)
            {
                v += (Q[i + M] & 0xFF) + Z * (X[i] & 0xFF);
                P[i + M] = (byte)v;
                v >>= 8;
            }

            return v;
        }

        /// <remarks>
        /// p += x * y * z  where z is a small integer.
        /// x is size 32, y is size t, p is size 32+t
        /// y is allowed to overlap with p+32 if you don't care about the upper half
        /// </remarks>
        private static int Mula32(byte[] P, byte[] X, byte[] Y, int T, int Z)
        {
            int n = 31;
            int w = 0;
            int i = 0;

            for (; i < T; i++)
            {
                int zy = Z * (Y[i] & 0xFF);
                w += MulaSmall(P, P, i, X, n, zy) + (P[i + n] & 0xFF) + zy * (X[n] & 0xFF);
                P[i + n] = (byte)w;
                w >>= 8;
            }

            P[i + n] = (byte)(w + (P[i + n] & 0xFF));

            return w >> 8;
        }

        /// <remarks>
        /// divide r (size n) by d (size t), returning quotient q and remainder r
        /// quotient is size n-t+1, remainder is size t
        /// requires t > 0 &amp; d[t-1] != 0
        /// requires that r[-1] and d[-1] are valid memory locations
        /// q may overlap with r+t
        /// </remarks>
        private static void DivMod(byte[] Q, byte[] R, int N, byte[] D, int T)
        {
            int rn = 0;
            int dt = ((D[T - 1] & 0xFF) << 8);

            if (T > 1)
                dt |= (D[T - 2] & 0xFF);
            
            while (N-- >= T)
            {
                int z = (rn << 16) | ((R[N] & 0xFF) << 8);
                if (N > 0)
                    z |= (R[N - 1] & 0xFF);

                z /= dt;
                rn += MulaSmall(R, R, N - T + 1, D, T, -z);
                Q[N - T + 1] = (byte)((z + rn) & 0xFF); // rn is 0 or -1 (underflow) 
                MulaSmall(R, R, N - T + 1, D, T, -rn);
                rn = (R[N] & 0xFF);
                R[N] = 0;
            }

            R[T - 1] = (byte)rn;
        }

        private static int NumSize(byte[] X, int N)
        {
            while (N-- != 0 && X[N] == 0);

            return N + 1;
        }

        /// <remarks>
        /// Returns x if a contains the gcd, y if b.
        /// Also, the returned buffer contains the inverse of a mod b, as 32-byte signed.
        /// x and y must have 64 bytes space for temporary use.
        /// requires that a[-1] and b[-1] are valid memory locations
        /// </remarks>
        private static byte[] Egcd32(byte[] X, byte[] Y, byte[] A, byte[] B)
        {
            int an, bn = 32, qn, i;

            for (i = 0; i < 32; i++)
                X[i] = Y[i] = 0;

            X[0] = 1;
            an = NumSize(A, 32);

            if (an == 0)
                return Y;	// division by zero

            byte[] temp = new byte[32];

            while (true)
            {
                qn = bn - an + 1;
                DivMod(temp, B, bn, A, an);
                bn = NumSize(B, bn);

                if (bn == 0)
                    return X;

                Mula32(Y, X, temp, qn, -1);

                qn = an - bn + 1;
                DivMod(temp, A, an, B, bn);
                an = NumSize(A, an);

                if (an == 0)
                    return Y;

                Mula32(X, Y, temp, qn, -1);
            }
        }

        /// <remarks>
        /// Convert to internal format from little-endian byte format
        /// </remarks>
        private static void Unpack(Long10 X, byte[] M)
        {
            X.N0 = ((M[0] & 0xFF)) | ((M[1] & 0xFF)) << 8 | (M[2] & 0xFF) << 16 | ((M[3] & 0xFF) & 3) << 24;
            X.N1 = ((M[3] & 0xFF) & ~3) >> 2 | (M[4] & 0xFF) << 6 | (M[5] & 0xFF) << 14 | ((M[6] & 0xFF) & 7) << 22;
            X.N2 = ((M[6] & 0xFF) & ~7) >> 3 | (M[7] & 0xFF) << 5 | (M[8] & 0xFF) << 13 | ((M[9] & 0xFF) & 31) << 21;
            X.N3 = ((M[9] & 0xFF) & ~31) >> 5 | (M[10] & 0xFF) << 3 | (M[11] & 0xFF) << 11 | ((M[12] & 0xFF) & 63) << 19;
            X.N4 = ((M[12] & 0xFF) & ~63) >> 6 | (M[13] & 0xFF) << 2 | (M[14] & 0xFF) << 10 | (M[15] & 0xFF) << 18;
            X.N5 = (M[16] & 0xFF) | (M[17] & 0xFF) << 8 | (M[18] & 0xFF) << 16 | ((M[19] & 0xFF) & 1) << 24;
            X.N6 = ((M[19] & 0xFF) & ~1) >> 1 | (M[20] & 0xFF) << 7 | (M[21] & 0xFF) << 15 | ((M[22] & 0xFF) & 7) << 23;
            X.N7 = ((M[22] & 0xFF) & ~7) >> 3 | (M[23] & 0xFF) << 5 | (M[24] & 0xFF) << 13 | ((M[25] & 0xFF) & 15) << 21;
            X.N8 = ((M[25] & 0xFF) & ~15) >> 4 | (M[26] & 0xFF) << 4 | (M[27] & 0xFF) << 12 | ((M[28] & 0xFF) & 63) << 20;
            X.N9 = ((M[28] & 0xFF) & ~63) >> 6 | (M[29] & 0xFF) << 2 | (M[30] & 0xFF) << 10 | (M[31] & 0xFF) << 18;
        }

        /// <remarks>
        /// Check if reduced-form input >= 2^255-19
        /// </remarks>
        private static bool IsOverflow(Long10 X)
        {
            return (((X.N0 > P26 - 19)) && ((X.N1 & X.N3 & X.N5 & X.N7 & X.N9) == P25) &&
                ((X.N2 & X.N4 & X.N6 & X.N8) == P26)) || (X.N9 > P25);
        }

        /// <remarks>
        /// Convert from internal format to little-endian byte format. 
        /// The number must be in a reduced form which is output by the following ops:
        /// unpack, mul, sqr
        /// set --  if input in range 0 .. P25
        /// If you're unsure if the number is reduced, first multiply it by 1.
        /// </remarks>
        private static void Pack(Long10 X, byte[] M)
        {
            int ld = 0, ud = 0;
            long t;

            ld = (IsOverflow(X) ? 1 : 0) - ((X.N9 < 0) ? 1 : 0);
            ud = ld * -(P25 + 1);
            ld *= 19;

            t = ld + X.N0 + (X.N1 << 26);
            M[0] = (byte)t;
            M[1] = (byte)(t >> 8);
            M[2] = (byte)(t >> 16);
            M[3] = (byte)(t >> 24);

            t = (t >> 32) + (X.N2 << 19);
            M[4] = (byte)t;
            M[5] = (byte)(t >> 8);
            M[6] = (byte)(t >> 16);
            M[7] = (byte)(t >> 24);

            t = (t >> 32) + (X.N3 << 13);
            M[8] = (byte)t;
            M[9] = (byte)(t >> 8);
            M[10] = (byte)(t >> 16);
            M[11] = (byte)(t >> 24);

            t = (t >> 32) + (X.N4 << 6);
            M[12] = (byte)t;
            M[13] = (byte)(t >> 8);
            M[14] = (byte)(t >> 16);
            M[15] = (byte)(t >> 24);

            t = (t >> 32) + X.N5 + (X.N6 << 25);
            M[16] = (byte)t;
            M[17] = (byte)(t >> 8);
            M[18] = (byte)(t >> 16);
            M[19] = (byte)(t >> 24);

            t = (t >> 32) + (X.N7 << 19);
            M[20] = (byte)t;
            M[21] = (byte)(t >> 8);
            M[22] = (byte)(t >> 16);
            M[23] = (byte)(t >> 24);

            t = (t >> 32) + (X.N8 << 12);
            M[24] = (byte)t;
            M[25] = (byte)(t >> 8);
            M[26] = (byte)(t >> 16);
            M[27] = (byte)(t >> 24);

            t = (t >> 32) + ((X.N9 + ud) << 6);
            M[28] = (byte)t;
            M[29] = (byte)(t >> 8);
            M[30] = (byte)(t >> 16);
            M[31] = (byte)(t >> 24);
        }

        /// <remarks>
        /// Copy a number
        /// </remarks>
        private static void Copy(Long10 NumOut, Long10 NumIn)
        {
            NumOut.N0 = NumIn.N0; NumOut.N1 = NumIn.N1;
            NumOut.N2 = NumIn.N2; NumOut.N3 = NumIn.N3;
            NumOut.N4 = NumIn.N4; NumOut.N5 = NumIn.N5;
            NumOut.N6 = NumIn.N6; NumOut.N7 = NumIn.N7;
            NumOut.N8 = NumIn.N8; NumOut.N9 = NumIn.N9;
        }

        /// <remarks>
        /// Set a number to value, which must be in range -185861411 .. 185861411
        /// </remarks>
        private static void Set(Long10 NumOut, int NumIn)
        {
            NumOut.N0 = NumIn; NumOut.N1 = 0;
            NumOut.N2 = 0; NumOut.N3 = 0;
            NumOut.N4 = 0; NumOut.N5 = 0;
            NumOut.N6 = 0; NumOut.N7 = 0;
            NumOut.N8 = 0; NumOut.N9 = 0;
        }

        /// <remarks>
        /// Add/subtract two numbers.  The inputs must be in reduced form, and the 
        /// output isn't, so to do another addition or subtraction on the output, 
        /// first multiply it by one to reduce it. 
        /// </remarks>
        private static void AddXY(Long10 XY, Long10 X, Long10 Y)
        {
            XY.N0 = X.N0 + Y.N0; XY.N1 = X.N1 + Y.N1;
            XY.N2 = X.N2 + Y.N2; XY.N3 = X.N3 + Y.N3;
            XY.N4 = X.N4 + Y.N4; XY.N5 = X.N5 + Y.N5;
            XY.N6 = X.N6 + Y.N6; XY.N7 = X.N7 + Y.N7;
            XY.N8 = X.N8 + Y.N8; XY.N9 = X.N9 + Y.N9;
        }

        private static void Sub(Long10 XY, Long10 X, Long10 Y)
        {
            XY.N0 = X.N0 - Y.N0; XY.N1 = X.N1 - Y.N1;
            XY.N2 = X.N2 - Y.N2; XY.N3 = X.N3 - Y.N3;
            XY.N4 = X.N4 - Y.N4; XY.N5 = X.N5 - Y.N5;
            XY.N6 = X.N6 - Y.N6; XY.N7 = X.N7 - Y.N7;
            XY.N8 = X.N8 - Y.N8; XY.N9 = X.N9 - Y.N9;
        }

        /// <remarks>
        /// Multiply a number by a small integer in range -185861411 .. 185861411.
        /// The output is in reduced form, the input x need not be.  x and xy may point
        /// to the same buffer. 
        /// </remarks>
        private static Long10 MulSmall(Long10 XY, Long10 X, long Y)
        {
            long t;

            t = (X.N8 * Y);
            XY.N8 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (X.N9 * Y);
            XY.N9 = (t & ((1 << 25) - 1));
            t = 19 * (t >> 25) + (X.N0 * Y);
            XY.N0 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (X.N1 * Y);
            XY.N1 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (X.N2 * Y);
            XY.N2 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (X.N3 * Y);
            XY.N3 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (X.N4 * Y);
            XY.N4 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (X.N5 * Y);
            XY.N5 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (X.N6 * Y);
            XY.N6 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (X.N7 * Y);
            XY.N7 = (t & ((1 << 25) - 1));
            t = (t >> 25) + XY.N8;
            XY.N8 = (t & ((1 << 26) - 1));
            XY.N9 += (t >> 26);

            return XY;
        }

        /// <remarks>
        /// Multiply two numbers.  The output is in reduced form, the inputs need not be.
        /// </remarks>
        private static Long10 Mul(Long10 XY, Long10 X, Long10 Y)
        {
            // sahn0:
            // Using local variables to avoid class access.
            // This seem to improve performance a bit...
            long x0 = X.N0, x1 = X.N1, x2 = X.N2, x3 = X.N3, x4 = X.N4, x5 = X.N5, x6 = X.N6, x7 = X.N7, x8 = X.N8, x9 = X.N9;
            long y0 = Y.N0, y1 = Y.N1, y2 = Y.N2, y3 = Y.N3, y4 = Y.N4, y5 = Y.N5, y6 = Y.N6, y7 = Y.N7, y8 = Y.N8, y9 = Y.N9;
            long t;

            t = (x0 * y8) + (x2 * y6) + (x4 * y4) + (x6 * y2) + (x8 * y0) + 2 * ((x1 * y7) + (x3 * y5) + (x5 * y3) + (x7 * y1)) + 38 * (x9 * y9);
            XY.N8 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (x0 * y9) + (x1 * y8) + (x2 * y7) + (x3 * y6) + (x4 * y5) + (x5 * y4) + (x6 * y3) + (x7 * y2) + (x8 * y1) + (x9 * y0);
            XY.N9 = (t & ((1 << 25) - 1));
            t = (x0 * y0) + 19 * ((t >> 25) + (x2 * y8) + (x4 * y6) + (x6 * y4) + (x8 * y2)) + 38 * ((x1 * y9) + (x3 * y7) + (x5 * y5) + (x7 * y3) + (x9 * y1));
            XY.N0 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (x0 * y1) + (x1 * y0) + 19 * ((x2 * y9) + (x3 * y8) + (x4 * y7) + (x5 * y6) + (x6 * y5) + (x7 * y4) + (x8 * y3) + (x9 * y2));
            XY.N1 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (x0 * y2) + (x2 * y0) + 19 * ((x4 * y8) + (x6 * y6) + (x8 * y4)) + 2 * (x1 * y1) + 38 * ((x3 * y9) + (x5 * y7) + (x7 * y5) + (x9 * y3));
            XY.N2 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (x0 * y3) + (x1 * y2) + (x2 * y1) + (x3 * y0) + 19 * ((x4 * y9) + (x5 * y8) + (x6 * y7) + (x7 * y6) + (x8 * y5) + (x9 * y4));
            XY.N3 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (x0 * y4) + (x2 * y2) + (x4 * y0) + 19 * ((x6 * y8) + (x8 * y6)) + 2 * ((x1 * y3) + (x3 * y1)) + 38 * ((x5 * y9) + (x7 * y7) + (x9 * y5));
            XY.N4 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (x0 * y5) + (x1 * y4) + (x2 * y3) + (x3 * y2) + (x4 * y1) + (x5 * y0) + 19 * ((x6 * y9) + (x7 * y8) + (x8 * y7) + (x9 * y6));
            XY.N5 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (x0 * y6) + (x2 * y4) + (x4 * y2) + (x6 * y0) + 19 * (x8 * y8) + 2 * ((x1 * y5) + (x3 * y3) + (x5 * y1)) + 38 * ((x7 * y9) + (x9 * y7));
            XY.N6 = (t & ((1 << 26) - 1));
            t = (t >> 26) + (x0 * y7) + (x1 * y6) + (x2 * y5) + (x3 * y4) + (x4 * y3) + (x5 * y2) + (x6 * y1) + (x7 * y0) + 19 * ((x8 * y9) + (x9 * y8));
            XY.N7 = (t & ((1 << 25) - 1));
            t = (t >> 25) + XY.N8;
            XY.N8 = (t & ((1 << 26) - 1));
            XY.N9 += (t >> 26);

            return XY;
        }

        /// <remarks>
        /// Square a number. Optimization of  mul25519(x2, x, x)
        /// </remarks>
        private static Long10 Sqr(Long10 X2, Long10 X)
        {
            long x0 = X.N0, x1 = X.N1, x2 = X.N2, x3 = X.N3, x4 = X.N4, x5 = X.N5, x6 = X.N6, x7 = X.N7, x8 = X.N8, x9 = X.N9;
            long t;

            t = (x4 * x4) + 2 * ((x0 * x8) + (x2 * x6)) + 38 * (x9 * x9) + 4 * ((x1 * x7) + (x3 * x5));
            X2.N8 = (t & ((1 << 26) - 1));
            t = (t >> 26) + 2 * ((x0 * x9) + (x1 * x8) + (x2 * x7) + (x3 * x6) + (x4 * x5));
            X2.N9 = (t & ((1 << 25) - 1));
            t = 19 * (t >> 25) + (x0 * x0) + 38 * ((x2 * x8) + (x4 * x6) + (x5 * x5)) + 76 * ((x1 * x9) + (x3 * x7));
            X2.N0 = (t & ((1 << 26) - 1));
            t = (t >> 26) + 2 * (x0 * x1) + 38 * ((x2 * x9) + (x3 * x8) + (x4 * x7) + (x5 * x6));
            X2.N1 = (t & ((1 << 25) - 1));
            t = (t >> 25) + 19 * (x6 * x6) + 2 * ((x0 * x2) + (x1 * x1)) + 38 * (x4 * x8) + 76 * ((x3 * x9) + (x5 * x7));
            X2.N2 = (t & ((1 << 26) - 1));
            t = (t >> 26) + 2 * ((x0 * x3) + (x1 * x2)) + 38 * ((x4 * x9) + (x5 * x8) + (x6 * x7));
            X2.N3 = (t & ((1 << 25) - 1));
            t = (t >> 25) + (x2 * x2) + 2 * (x0 * x4) + 38 * ((x6 * x8) + (x7 * x7)) + 4 * (x1 * x3) + 76 * (x5 * x9);
            X2.N4 = (t & ((1 << 26) - 1));
            t = (t >> 26) + 2 * ((x0 * x5) + (x1 * x4) + (x2 * x3)) + 38 * ((x6 * x9) + (x7 * x8));
            X2.N5 = (t & ((1 << 25) - 1));
            t = (t >> 25) + 19 * (x8 * x8) + 2 * ((x0 * x6) + (x2 * x4) + (x3 * x3)) + 4 * (x1 * x5) + 76 * (x7 * x9);
            X2.N6 = (t & ((1 << 26) - 1));
            t = (t >> 26) + 2 * ((x0 * x7) + (x1 * x6) + (x2 * x5) + (x3 * x4)) + 38 * (x8 * x9);
            X2.N7 = (t & ((1 << 25) - 1));
            t = (t >> 25) + X2.N8;
            X2.N8 = (t & ((1 << 26) - 1));
            X2.N9 += (t >> 26);

            return X2;
        }

        /// <remarks>
        /// Calculates a reciprocal. The output is in reduced form, the inputs need not be. 
        /// Simply calculates  y = x^(p-2)  so it's not too fast. 
        /// When sqrtassist is true, it instead calculates y = x^((p-5)/8)
        /// </remarks>
        private static void Recip(Long10 Y, Long10 X, int SqrtAssist)
        {
            Long10 t0 = new Long10(), t1 = new Long10(), t2 = new Long10(), t3 = new Long10(), t4 = new Long10();
            int i;

            // the chain for x^(2^255-21) is straight from djb's implementation 
            Sqr(t1, X);	        //  2 == 2 * 1	
            Sqr(t2, t1);	    //  4 == 2 * 2	
            Sqr(t0, t2);	    //  8 == 2 * 4	
            Mul(t2, t0, X);	    //  9 == 8 + 1	
            Mul(t0, t2, t1);	// 11 == 9 + 2	
            Sqr(t1, t0);	    // 22 == 2 * 11	
            Mul(t3, t1, t2);	// 31 == 22 + 9
            Sqr(t1, t3);	    // 2^6  - 2^1	
            Sqr(t2, t1);	    // 2^7  - 2^2	
            Sqr(t1, t2);	    // 2^8  - 2^3	
            Sqr(t2, t1);	    // 2^9  - 2^4	
            Sqr(t1, t2);	    // 2^10 - 2^5	
            Mul(t2, t1, t3);	// 2^10 - 2^0	
            Sqr(t1, t2);	    // 2^11 - 2^1	
            Sqr(t3, t1);	    // 2^12 - 2^2	

            for (i = 1; i < 5; i++) // 2^20  - 2^10	
            {
                Sqr(t1, t3);
                Sqr(t3, t1);
            }

            // t3 
            Mul(t1, t3, t2);	// 2^20  - 2^0	
            Sqr(t3, t1);	    // 2^21  - 2^1	
            Sqr(t4, t3);	    // 2^22  - 2^2	
            for (i = 1; i < 10; i++) // 2^40  - 2^20	
            {
                Sqr(t3, t4);
                Sqr(t4, t3);
            }

            // t4 	
            Mul(t3, t4, t1);        // 2^40  - 2^0	
            for (i = 0; i < 5; i++) // 2^50  - 2^10	
            {
                Sqr(t1, t3);
                Sqr(t3, t1);
            } 

            // t3 	
            Mul(t1, t3, t2);	// 2^50  - 2^0	
            Sqr(t2, t1);	    // 2^51  - 2^1	
            Sqr(t3, t2);	    // 2^52  - 2^2	
            for (i = 1; i < 25; i++) // 2^100 - 2^50 
            {
                Sqr(t2, t3);
                Sqr(t3, t2);
            } 

            // t3 
            Mul(t2, t3, t1);	// 2^100 - 2^0	
            Sqr(t3, t2);	    // 2^101 - 2^1	
            Sqr(t4, t3);	    // 2^102 - 2^2	
            for (i = 1; i < 50; i++) // 2^200 - 2^100 
            {
                Sqr(t3, t4);
                Sqr(t4, t3);
            } 

            // t4 		
            Mul(t3, t4, t2);	// 2^200 - 2^0	
            for (i = 0; i < 25; i++) // 2^250 - 2^50	
            {
                Sqr(t4, t3);
                Sqr(t3, t4);
            } 

            // t3 		
            Mul(t2, t3, t1);	// 2^250 - 2^0	
            Sqr(t1, t2);	    // 2^251 - 2^1	
            Sqr(t2, t1);	    // 2^252 - 2^2	

            if (SqrtAssist != 0)
            {
                Mul(Y, X, t2);	// 2^252 - 3 
            }
            else
            {
                Sqr(t1, t2);	// 2^253 - 2^3	
                Sqr(t2, t1);	// 2^254 - 2^4	
                Sqr(t1, t2);	// 2^255 - 2^5	
                Mul(Y, t1, t0);	// 2^255 - 21	
            }
        }

        /// <remarks>
        /// Checks if x is "negative", requires reduced input 
        /// </remarks>
        private static int IsNegative(Long10 X)
        {
            return (int)(((IsOverflow(X) || (X.N9 < 0)) ? 1 : 0) ^ (X.N0 & 1));
        }

        /// <remarks>
        /// A square root
        /// </remarks>
        private static void Sqrt(Long10 X, Long10 U)
        {
            Long10 val = new Long10(), t1 = new Long10(), t2 = new Long10();

            AddXY(t1, U, U);	// t1 = 2u		
            Recip(val, t1, 1);	// v = (2u)^((p-5)/8)	
            Sqr(X, val);		// x = v^2		
            Mul(t2, t1, X);	    // t2 = 2uv^2		
            t2.N0--;		    // t2 = 2uv^2-1		
            Mul(t1, val, t2);	// t1 = v(2uv^2-1)	
            Mul(X, U, t1);	    // x = uv(2uv^2-1)	
        }

        /// <remarks>
        /// t1 = ax + az
        /// t2 = ax - az 
        /// </remarks>
        private static void MontPrep(Long10 T1, Long10 T2, Long10 Ax, Long10 Az)
        {
            AddXY(T1, Ax, Az);
            Sub(T2, Ax, Az);
        }

        /// <remarks>
        /// A = P + Q   where:
        /// X(A) = ax/az
        /// X(P) = (t1+t2)/(t1-t2)
        /// X(Q) = (t3+t4)/(t3-t4)
        /// X(P-Q) = dx
        /// clobbers t1 and t2, preserves t3 and t4 
        /// </remarks>
        private static void MontAdd(Long10 T1, Long10 T2, Long10 T3, Long10 T4, Long10 Ax, Long10 Az, Long10 Dx)
        {
            Mul(Ax, T2, T3);
            Mul(Az, T1, T4);
            AddXY(T1, Ax, Az);
            Sub(T2, Ax, Az);
            Sqr(Ax, T1);
            Sqr(T1, T2);
            Mul(Az, T1, Dx);
        }

        /// <remarks>
        /// B = 2 * Q   where:
        /// X(B) = bx/bz
        /// X(Q) = (t3+t4)/(t3-t4)
        /// clobbers t1 and t2, preserves t3 and t4
        /// </remarks>
        private static void MontDbl(Long10 T1, Long10 T2, Long10 T3, Long10 T4, Long10 Bx, Long10 Bz)
        {
            Sqr(T1, T3);
            Sqr(T2, T4);
            Mul(Bx, T1, T2);
            Sub(T2, T1, T2);
            MulSmall(Bz, T2, 121665);
            AddXY(T1, T1, Bz);
            Mul(Bz, T1, T2);
        }

        /// <remarks>
        /// Y^2 = X^3 + 486662 X^2 + X
        /// t is a temporary
        /// </remarks>
        private static void XtoY2(Long10 T, Long10 Y2, Long10 X)
        {
            Sqr(T, X);
            MulSmall(Y2, X, 486662);
            AddXY(T, T, Y2);
            T.N0++;
            Mul(Y2, T, X);
        }

        /// <remarks>
        /// P = kG   and  s = sign(P)/k
        /// </remarks>
        private static void Core(byte[] Px, byte[] S, byte[] K, byte[] Gx)
        {
            Long10 dx = new Long10(), t1 = new Long10(), t2 = new Long10(), t3 = new Long10(), t4 = new Long10();
            Long10[] x = new Long10[] { new Long10(), new Long10() }, z = new Long10[] { new Long10(), new Long10() };
            int i, j;

            // unpack the base
            if (Gx != null)
                Unpack(dx, Gx);
            else
                Set(dx, 9);

            // 0G = point-at-infinity
            Set(x[0], 1);
            Set(z[0], 0);

            // 1G = G 
            Copy(x[1], dx);
            Set(z[1], 1);

            for (i = 32; i-- != 0; )
            {
                if (i == 0)
                    i = 0;
                
                for (j = 8; j-- != 0; )
                {
                    // swap arguments depending on bit 
                    int bit1 = (K[i] & 0xFF) >> j & 1;
                    int bit0 = ~(K[i] & 0xFF) >> j & 1;
                    Long10 ax = x[bit0];
                    Long10 az = z[bit0];
                    Long10 bx = x[bit1];
                    Long10 bz = z[bit1];

                    // a' = a + b	
                    // b' = 2 b	
                    MontPrep(t1, t2, ax, az);
                    MontPrep(t3, t4, bx, bz);
                    MontAdd(t1, t2, t3, t4, ax, az, dx);
                    MontDbl(t1, t2, t3, t4, bx, bz);
                }
            }

            Recip(t1, z[0], 0);
            Mul(dx, x[0], t1);
            Pack(dx, Px);

            // calculate s such that s abs(P) = G  .. assumes G is std base point 
            if (S != null)
            {
                XtoY2(t2, t1, dx);	        // t1 = Py^2  
                Recip(t3, z[1], 0);	        // where Q=P+G ... 
                Mul(t2, x[1], t3);	        // t2 = Qx  
                AddXY(t2, t2, dx);	        // t2 = Qx + Px  
                t2.N0 += 9 + 486662;	    // t2 = Qx + Px + Gx + 486662  
                dx.N0 -= 9;		            // dx = Px - Gx  
                Sqr(t3, dx);	            // t3 = (Px - Gx)^2  
                Mul(dx, t2, t3);	        // dx = t2 (Px - Gx)^2  
                Sub(dx, dx, t1);	        // dx = t2 (Px - Gx)^2 - Py^2  
                dx.N0 -= 39420360;	        // dx = t2 (Px - Gx)^2 - Py^2 - Gy^2  
                Mul(t1, dx, BASE_R2Y);	    // t1 = -Py  

                if (IsNegative(t1) != 0)	// sign is 1, so just copy  
                    Copy32(S, K);
                else			            // sign is -1, so negate  
                    MulaSmall(S, ORDER_TIMES_8, 0, K, 32, -1);

                // reduce s mod q (is this needed?  do it just in case, it's fast anyway) 
                // divmod((dstptr) t1, s, 32, order25519, 32);

                // take reciprocal of s mod q 
                byte[] temp1 = new byte[32];
                byte[] temp2 = new byte[64];
                byte[] temp3 = new byte[64];

                Copy32(temp1, ORDER);
                Copy32(S, Egcd32(temp2, temp3, S, temp1));

                if ((S[31] & 0x80) != 0)
                    MulaSmall(S, S, 0, ORDER, 32, 1);
            }
        }
        #endregion
    }
}
