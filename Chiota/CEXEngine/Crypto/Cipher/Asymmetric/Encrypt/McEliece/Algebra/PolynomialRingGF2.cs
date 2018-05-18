#region Directives
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class describes operations with polynomials over finite field GF(2), i e polynomial ring R = GF(2)[X].
    /// <para>All operations are defined only for polynomials with degree &lt;=32.
    /// For the polynomial representation the map f: R-&gt;Z, poly(X)-&gt;poly(2) is used,
    /// where integers have the binary representation.
    /// For example: X^7+X^3+X+1 -&gt; (00...0010001011)=139 Also for polynomials type Integer is used.</para>
    /// </summary>
    internal sealed class PolynomialRingGF2
    {
        #region Constructor
        /// <summary>
        /// Default constructor (private)
        /// </summary>
        private PolynomialRingGF2()
        {
        }
        #endregion

        #region Methods
        /// <summary>
        /// Return sum of two polyomials
        /// </summary>
        /// 
        /// <param name="P">The P polynomial</param>
        /// <param name="Q">The Q polynomial</param>
        /// 
        /// <returns>Returns <c>P+Q</c></returns>
        public static int Add(int P, int Q)
        {
            return P ^ Q;
        }

        /// <summary>
        /// Return the degree of a polynomial
        /// </summary>
        /// 
        /// <param name="P">The polynomial</param>
        /// 
        /// <returns>Returns Degree(p)</returns>
        public static int Degree(int P)
        {
            int result = -1;
            while (P != 0)
            {
                result++;
                P >>= 1;
            }

            return result;
        }

        /// <summary>
        /// Return the degree of a long polynomial
        /// </summary>
        /// 
        /// <param name="P">The polynomial</param>
        /// 
        /// <returns>Returns Degree(p)</returns>
        public static int Degree(long P)
        {
            int result = 0;
            while (P != 0)
            {
                result++;
                P >>= 1;
            }

            return result - 1;
        }

        /// <summary>
        /// Return the greatest common divisor of two polynomials
        /// </summary>
        /// 
        /// <param name="P">The P polynomial</param>
        /// <param name="Q">The Q polynomial</param>
        /// 
        /// <returns>Returns Gcd(p, q)</returns>
        public static int Gcd(int P, int Q)
        {
            int a, b, c;
            a = P;
            b = Q;

            while (b != 0)
            {
                c = Remainder(a, b);
                a = b;
                b = c;
            }

            return a;
        }

        /// <summary>
        /// Creates irreducible polynomial with Degree
        /// </summary>
        /// 
        /// <param name="Degree">The polynomial degree</param>
        /// 
        /// <returns>Returns the irreducible polynomial</returns>
        public static int GetIrreduciblePolynomial(int Degree)
        {
            if (Degree < 0)
                return 0;
            if (Degree > 31)
                return 0;
            if (Degree == 0)
                return 1;

            int a = 1 << Degree;
            a++;
            int b = 1 << (Degree + 1);

            for (int i = a; i < b; i += 2)
            {
                if (IsIrreducible(i))
                    return i;
            }

            return 0;
        }

        /// <summary>
        /// Checking polynomial for irreducibility
        /// </summary>
        /// 
        /// <param name="P">The polinomial</param>
        /// 
        /// <returns>Returns true if p is irreducible and false otherwise</returns>
        public static bool IsIrreducible(int P)
        {
            if (P == 0)
                return false;
            int d = IntUtils.URShift(Degree(P), 1);
            int u = 2;

            for (int i = 0; i < d; i++)
            {
                u = ModMultiply(u, u, P);
                if (Gcd(u ^ 2, P) != 1)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compute the product of two polynomials modulo a third polynomial
        /// </summary>
        /// 
        /// <param name="A">The first polynomial</param>
        /// <param name="B">The second polynomial</param>
        /// <param name="R">The reduction polynomial</param>
        /// 
        /// <returns>Returns <c>a * b mod r</c></returns>
        public static int ModMultiply(int A, int B, int R)
        {
            int result = 0;
            int p = Remainder(A, R);
            int q = Remainder(B, R);

            if (q != 0)
            {
                int d = 1 << Degree(R);

                while (p != 0)
                {
                    byte pMod2 = (byte)(p & 0x01);
                    if (pMod2 == 1)
                        result ^= q;
                    p = IntUtils.URShift(p, 1);
                    q <<= 1;
                    if (q >= d)
                        q ^= R;
                }
            }
            return result;
        }

        /// <summary>
        /// Return product of two polynomials
        /// </summary>
        /// 
        /// <param name="P">The P polynomial</param>
        /// <param name="Q">The Q polynomial</param>
        /// 
        /// <returns>Returns <c>P*Q</c></returns>
        public static long Multiply(int P, int Q)
        {
            long result = 0;
            if (Q != 0)
            {
                long q1 = Q & 0x00000000ffffffffL;

                while (P != 0)
                {
                    byte b = (byte)(P & 0x01);
                    if (b == 1)
                        result ^= q1;
                    P = IntUtils.URShift(P, 1);
                    q1 <<= 1;

                }
            }
            return result;
        }

        /// <summary>
        /// Return the remainder of a polynomial division of two polynomials
        /// </summary>
        /// 
        /// <param name="P">The dividend</param>
        /// <param name="Q">The divisor</param>
        /// 
        /// <returns>Returns <c>P mod Q</c></returns>
        public static int Remainder(int P, int Q)
        {
            int result = P;

            if (Q == 0)
                return 0;

            while (Degree(result) >= Degree(Q))
                result ^= Q << (Degree(result) - Degree(Q));

            return result;
        }

        /// <summary>
        /// Return the resultant of division two polynomials
        /// </summary>
        /// 
        /// <param name="P">The P polynomial</param>
        /// <param name="Q">The Q polynomial</param>
        /// 
        /// <returns>The rest value</returns>
        public static int Rest(long P, int Q)
        {
            long p1 = P;
            if (Q == 0)
                return 0;

            long q1 = Q & 0x00000000ffffffffL;
            while ((IntUtils.URShift(p1, 32)) != 0)
                p1 ^= q1 << (Degree(p1) - Degree(q1));

            int result = (int)(p1 & 0xffffffff);
            while (Degree(result) >= Degree(Q))
                result ^= Q << (Degree(result) - Degree(Q));

            return result;
        }
        #endregion
    }
}
