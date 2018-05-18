#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// Provides methods for CCA2-Secure Conversions of McEliece PKCS
    /// </summary>
    internal static class CCA2Conversions
    {
        #region Fields
        private static readonly BigInteger ZERO = BigInteger.ValueOf(0);
        private static readonly BigInteger ONE = BigInteger.ValueOf(1);
        #endregion

        #region Internal Methods
        /// <summary>
        /// Encode a number between 0 and (n|t) (binomial coefficient) into a binary vector of length n with weight t. 
        /// <para>The number is given as a byte array. Only the first s bits are used, where s = floor[log(n|t)].</para>
        /// </summary>
        /// 
        /// <param name="N">The "n" integer</param>
        /// <param name="T">The "t" integer</param>
        /// <param name="M">The message as a byte array</param>
        /// 
        /// <returns>The encoded message as GF2Vector</returns>
        public static GF2Vector Encode(int N, int T, byte[] M)
        {
            if (N < T)
                throw new ArgumentException("n < t");

            // compute the binomial c = (n|t)
            BigInteger c = BigMath.Binomial(N, T);
            // get the number encoded in m
            BigInteger i = new BigInteger(1, M);
            // compare
            if (i.CompareTo(c) >= 0)
                throw new ArgumentException("Encoded number too large.");

            GF2Vector result = new GF2Vector(N);
            int nn = N;
            int tt = T;

            for (int j = 0; j < N; j++)
            {
                c = c.Multiply(BigInteger.ValueOf(nn - tt)).Divide(BigInteger.ValueOf(nn));
                nn--;

                if (c.CompareTo(i) <= 0)
                {
                    result.SetBit(j);
                    i = i.Subtract(c);
                    tt--;

                    if (nn == tt)
                        c = ONE;
                    else
                        c = (c.Multiply(BigInteger.ValueOf(tt + 1))).Divide(BigInteger.ValueOf(nn - tt));
                }
            }

            return result;
        }

        /// <summary>
        /// Decode a binary vector of length n and weight t into a number between 0 and (n|t) (binomial coefficient).
        /// <para>The result is given as a byte array of length floor[(s+7)/8], where s = floor[log(n|t)].</para>
        /// </summary>
        /// 
        /// <param name="N">The "n" integer</param>
        /// <param name="T">The "t" integer</param>
        /// <param name="GVector">The binary vector</param>
        /// 
        /// <returns>The decoded vector as a byte array</returns>
        public static byte[] Decode(int N, int T, GF2Vector GVector)
        {
            if ((GVector.Length != N) || (GVector.HammingWeight() != T))
                throw new ArgumentException("vector has wrong length or hamming weight");

            int[] vecArray = GVector.VectorArray;
            BigInteger bc = BigMath.Binomial(N, T);
            BigInteger d = ZERO;
            int nn = N;
            int tt = T;

            for (int i = 0; i < N; i++)
            {
                bc = bc.Multiply(BigInteger.ValueOf(nn - tt)).Divide(BigInteger.ValueOf(nn));
                nn--;

                int q = i >> 5;
                int e = vecArray[q] & (1 << (i & 0x1f));
                if (e != 0)
                {
                    d = d.Add(bc);
                    tt--;

                    if (nn == tt)
                        bc = ONE;
                    else
                        bc = bc.Multiply(BigInteger.ValueOf(tt + 1)).Divide(BigInteger.ValueOf(nn - tt));

                }
            }

            return BigIntUtils.ToMinimalByteArray(d);
        }

        /// <summary>
        /// Compute a message representative of a message given as a vector of length <c>n</c> bit and of hamming weight <c>t</c>. 
        /// <para>The result is a byte array of length <c>(s+7)/8</c>, where <c>s = floor[log(n|t)]</c>.</para>
        /// </summary>
        /// 
        /// <param name="N">The "n" integer</param>
        /// <param name="T">The "t" integer</param>
        /// <param name="M">The message vector as a byte array</param>
        /// 
        /// <returns>A message representative for <c>m</c></returns>
        public static byte[] SignConversion(int N, int T, byte[] M)
        {
            if (N < T)
                throw new ArgumentException("n < t");

            BigInteger bc = BigMath.Binomial(N, T);
            // finds s = floor[log(binomial(n,t))]
            int s = bc.BitLength - 1;
            // s = sq*8 + sr;
            int sq = s >> 3;
            int sr = s & 7;
            if (sr == 0)
            {
                sq--;
                sr = 8;
            }

            // n = nq*8+nr;
            int nq = N >> 3;
            int nr = N & 7;
            if (nr == 0)
            {
                nq--;
                nr = 8;
            }

            // take s bit from m
            byte[] data = new byte[nq + 1];
            if (M.Length < data.Length)
            {
                Array.Copy(M, 0, data, 0, M.Length);

                for (int i = M.Length; i < data.Length; i++)
                    data[i] = 0;
            }
            else
            {
                Array.Copy(M, 0, data, 0, nq);
                int h = (1 << nr) - 1;
                data[nq] = (byte)(h & M[nq]);
            }

            BigInteger d = ZERO;
            int nn = N;
            int tt = T;
            for (int i = 0; i < N; i++)
            {
                bc = (bc.Multiply(new BigInteger(IntUtils.ToString(nn - tt)))).Divide(new BigInteger(IntUtils.ToString(nn)));
                nn--;

                int q = IntUtils.URShift(i, 3);
                int r = i & 7;
                r = 1 << r;
                byte e = (byte)(r & data[q]);

                if (e != 0)
                {
                    d = d.Add(bc);
                    tt--;
                    if (nn == tt)
                        bc = ONE;
                    else
                        bc = (bc.Multiply(new BigInteger(IntUtils.ToString(tt + 1)))).Divide(new BigInteger(IntUtils.ToString(nn - tt)));
                }
            }

            byte[] result = new byte[sq + 1];
            byte[] help = d.ToByteArray();
            if (help.Length < result.Length)
            {
                Array.Copy(help, 0, result, 0, help.Length);

                for (int i = help.Length; i < result.Length; i++)
                    result[i] = 0;
            }
            else
            {
                Array.Copy(help, 0, result, 0, sq);
                result[sq] = (byte)(((1 << sr) - 1) & help[sq]);
            }

            return result;
        }
        #endregion
    }
}