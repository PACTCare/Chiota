#region Directives
using System;
using System.Collections.Generic;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Polynomial
{
    /// <summary>
    /// A polynomial with <c>integer</c> coefficients.
    /// <para>Some methods (like <c>Add</c>) change the polynomial, others (like <c>Multiply</c>) do not,
    /// but return the result as a new polynomial.</para>
    /// </summary>
    internal class IntegerPolynomial : IPolynomial
    {
        #region Constants
        private const int NUM_EQUAL_RESULTANTS = 3;
        #endregion

        #region Fields
        // Prime numbers greater than 4500 for resultant computation. Starting them below ~4400 causes incorrect results occasionally.
        // Fortunately, 4500 is about the optimum number for performance.
        // This array contains enough prime numbers so primes never have to be computed on-line for any standard SignatureParameters.
        private static readonly int[] PRIMES = new int[] 
        {
            4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
            4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
            4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
            4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
            4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
            4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
            5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
            5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
            5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
            5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
            5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
            5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
            5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
            5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
            5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
            5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
            5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
            5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
            6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
            6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
            6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
            6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
            6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
            6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
            6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
            6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
            6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
            6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
            6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
            7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
            7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
            7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
            7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
            7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
            7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
            7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
            7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
            7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
            7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
            7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
            8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111,
            8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219,
            8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
            8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387,
            8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501,
            8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
            8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677,
            8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741,
            8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831,
            8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929,
            8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011,
            9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
            9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199,
            9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283,
            9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377,
            9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439,
            9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533,
            9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
            9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733,
            9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811,
            9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887,
            9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973
        };

        private static List<BigInteger> BIGINT_PRIMES;
        /// <summary>
        /// should be marked as internal
        /// </summary>
        public int[] Coeffs;
        #endregion

        #region Constructors
        /// <summary>
        /// Static Constructor
        /// </summary>
        static IntegerPolynomial()
        {
            BIGINT_PRIMES = new List<BigInteger>();

            for (int i = 0; i < PRIMES.Length; i++)
                BIGINT_PRIMES.Add(BigInteger.ValueOf(PRIMES[i]));
        }

        /// <summary>
        /// Constructs a new polynomial with <c>N</c> coefficients initialized to 0
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        public IntegerPolynomial(int N)
        {
            Coeffs = new int[N];
        }

        /// <summary>
        /// Constructs a new polynomial with a given set of coefficients
        /// </summary>
        /// 
        /// <param name="Coeffs">The coefficients</param>
        public IntegerPolynomial(int[] Coeffs)
        {
            this.Coeffs = Coeffs;
        }

        /// <summary>
        /// Constructs a <c>IntegerPolynomial</c> from a <c>BigIntPolynomial</c>. The two polynomials are independent of each other
        /// </summary>
        /// 
        /// <param name="P">The original polynomial</param>
        public IntegerPolynomial(BigIntPolynomial P)
        {
            Coeffs = new int[P.Coeffs.Length];

            for (int i = 0; i < P.Coeffs.Length; i++)
                Coeffs[i] = P.Coeffs[i].ToInt32();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds a <c>TernaryPolynomial</c> which must not have more coefficients than <c>this</c> polynomial.
        /// </summary>
        /// 
        /// <param name="B">Another polynomial</param>
        public void Add(ITernaryPolynomial B)
        {
            foreach (int n in B.GetOnes())
                Coeffs[n]++;
            foreach (int n in B.GetNegOnes())
                Coeffs[n]--;
        }

        /// <summary>
        /// Adds another polynomial
        /// </summary>
        /// <param name="B">The polynomial to add</param> //p
        public void Add(IntegerPolynomial B)
        {
            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] += B.Coeffs[i];
        }

        /// <summary>
        /// Adds another polynomial which must not have more coefficients than <c>this</c>
        /// polynomial, and takes the coefficient values mod <c>modulus</c>.
        /// </summary>
        /// 
        /// <param name="B">The polynomial to add</param>
        /// <param name="Modulus">The modulus</param>
        public void Add(IntegerPolynomial B, int Modulus)
        {
            Add(B);
            Mod(Modulus);
        }

        /// <summary>
        /// Shifts the values of all coefficients to the interval <c>[-q/2, q/2]</c>.
        /// </summary>
        /// 
        /// <param name="Q">The Modulus</param>
        public void Center0(int Q)
        {
            if (Q == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                {
                    int c = Coeffs[i] & 2047;
                    if (c >= 1024)
                        c -= 2048;

                    Coeffs[i] = c;
                }
            }
            else
            {
                for (int i = 0; i < Coeffs.Length; i++)
                {
                    while (Coeffs[i] < -Q / 2)
                        Coeffs[i] += Q;
                    while (Coeffs[i] > Q / 2)
                        Coeffs[i] -= Q;
                }
            }
        }

        /// <summary>
        /// Computes the centered euclidean norm of the polynomial.
        /// </summary>
        /// 
        /// <param name="Q">The Modulus</param>
        /// 
        /// <returns>The centered norm</returns>
        public long CenteredNormSq(int Q)
        {
            int N = Coeffs.Length;
            IntegerPolynomial p = Clone();
            p.ShiftGap(Q);

            long sum = 0;
            long sqSum = 0;

            for (int i = 0; i < p.Coeffs.Length; i++)
            {
                int c = p.Coeffs[i];
                sum += c;
                sqSum += c * c;
            }

            long centeredNormSq = sqSum - sum * sum / N;
            return centeredNormSq;
        }

        /// <summary>
        /// Clear the coefficients
        /// </summary>
        public void Clear()
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] = 0;
        }

        /// <summary>
        /// Clone the polynomial
        /// </summary>
        /// <returns>The cloned polynomial</returns>
        public IntegerPolynomial Clone()
        {
            return new IntegerPolynomial((int[])Coeffs.Clone());
        }

        /// <summary>
        /// Counts the number of coefficients equal to an integer
        /// </summary>
        /// 
        /// <param name="Value">Value of an integer</param>
        /// 
        /// <returns>The number of coefficients equal to <c>value</c></returns>
        public int Count(int Value)
        {
            int count = 0;

            for (int i = 0; i < Coeffs.Length; i++)
            {
                if (Coeffs[i] == Value)
                    count++;
            }

            return count;
        }

        /// <summary>
        /// Divides each coefficient by <c>k</c> and rounds to the nearest integer.
        /// <para>Does not return a new polynomial but modifies this polynomial.</para>
        /// </summary>
        /// 
        /// <param name="Divisor">The divisor</param>
        public void Divide(int Divisor)
        {
            int ka = Divisor / 2;

            if (Divisor == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                    Coeffs[i] = (Coeffs[i] + ka) >> 11;
            }
            else
            {
                int kb = (1 - Divisor) / 2;
                for (int i = 0; i < Coeffs.Length; i++)
                {
                    Coeffs[i] += Coeffs[i] > 0 ? ka : kb;
                    Coeffs[i] /= Divisor;
                }
            }
        }

        /// <summary>
        /// Adds <c>modulus</c> until all coefficients are above 0.
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        public void EnsurePositive(int Modulus)
        {
            if (Modulus == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                    Coeffs[i] &= 2047;
            }
            else
            {
                for (int i = 0; i < Coeffs.Length; i++)
                {
                    while (Coeffs[i] < 0)
                        Coeffs[i] += Modulus;
                }
            }
        }

        /// <summary>
        /// Tests if <c>p(x) = 1</c>.
        /// </summary>
        /// 
        /// <returns>True iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1</returns>
        public bool EqualsOne()
        {
            for (int i = 1; i < Coeffs.Length; i++)
            {
                if (Coeffs[i] != 0)
                    return false;
            }

            return Coeffs[0] == 1;
        }

        /// <summary>
        /// Returns a polynomial with N coefficients between <c>0</c> and <c>q-1</c>.
        /// </summary>
        /// 
        /// <param name="Data">ata an encoded ternary polynomial</param>
        /// <param name="N"> number of coefficients</param>
        /// <param name="Q">Q value, must be a power of 2</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static IntegerPolynomial FromBinary(byte[] Data, int N, int Q)
        {
            return new IntegerPolynomial(ArrayEncoder.DecodeModQ(Data, N, Q));
        }
        //57861
        /// <summary>
        /// Returns a polynomial with N coefficients between <c>0</c> and <c>q-1</c>.
        /// </summary>
        /// 
        /// <param name="InputStream">An encoded ternary polynomial</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Q">Q value, must be a power of 2</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static IntegerPolynomial FromBinary(Stream InputStream, int N, int Q)
        {
            return new IntegerPolynomial(ArrayEncoder.DecodeModQ(InputStream, N, Q));
        }

        /// <summary>
        /// Decodes a byte array to a polynomial with <c>N</c> ternary coefficients.
        /// <para>Ignores any excess bytes.</para>
        /// </summary>
        /// 
        /// <param name="Data">Data an encoded ternary polynomial</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="SkipFirst">Whether to leave the constant coefficient zero and start populating at the linear coefficient</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static IntegerPolynomial FromBinary3Sves(byte[] Data, int N, bool SkipFirst)
        {
            return new IntegerPolynomial(ArrayEncoder.DecodeMod3Sves(Data, N, SkipFirst));
        }

        /// <summary>
        /// Converts a byte array produced by ToBinary3Tight() to a polynomial
        /// </summary>
        /// 
        /// <param name="B">A byte array</param>
        /// <param name="N">The number of coefficients</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static IntegerPolynomial FromBinary3Tight(byte[] B, int N)
        {
            return new IntegerPolynomial(ArrayEncoder.DecodeMod3Tight(B, N));
        }

        /// <summary>
        /// Reads data produced by ToBinary3Tight() from an input stream and converts it to a polynomial
        /// </summary>
        /// 
        /// <param name="InputStream">An input stream</param>
        /// <param name="N">The number of coefficients</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static IntegerPolynomial FromBinary3Tight(MemoryStream InputStream, int N)
        {
            return new IntegerPolynomial(ArrayEncoder.DecodeMod3Tight(InputStream, N));
        }

        /// <summary>
        /// Computes the inverse mod 3.
        /// <para>Returns <c>null</c> if the polynomial is not invertible.
        /// The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
        /// Almost Inverses and Fast NTRU Key Generation</a>.</para>
        /// </summary>
        /// 
        /// <returns>A new polynomial, or <c>null</c> if no inverse exists</returns>
        public IntegerPolynomial InvertF3()
        {
            int N = Coeffs.Length;
            int k = 0;
            IntegerPolynomial b = new IntegerPolynomial(N + 1);
            b.Coeffs[0] = 1;

            IntegerPolynomial c = new IntegerPolynomial(N + 1);
            IntegerPolynomial f = new IntegerPolynomial(N + 1);
            f.Coeffs = Coeffs.CopyOf(N + 1);
            f.ModPositive(3);

            // set g(x) = x^N − 1
            IntegerPolynomial g = new IntegerPolynomial(N + 1);
            g.Coeffs[0] = -1;
            g.Coeffs[N] = 1;

            while (true)
            {
                while (f.Coeffs[0] == 0)
                {
                    for (int i = 1; i <= N; i++)
                    {
                        f.Coeffs[i - 1] = f.Coeffs[i];   // f(x) = f(x) / x
                        c.Coeffs[N + 1 - i] = c.Coeffs[N - i];   // c(x) = c(x) * x
                    }

                    f.Coeffs[N] = 0;
                    c.Coeffs[0] = 0;
                    k++;

                    if (f.EqualsZero())
                        return null;   // not invertible
                }

                if (f.EqualsAbsOne())
                    break;

                if (f.Degree() < g.Degree())
                {
                    // exchange f and g
                    IntegerPolynomial temp = f;
                    f = g;
                    g = temp;
                    // exchange b and c
                    temp = b;
                    b = c;
                    c = temp;
                }

                if (f.Coeffs[0] == g.Coeffs[0])
                {
                    f.Subtract(g, 3);
                    b.Subtract(c, 3);
                }
                else
                {
                    f.Add(g, 3);
                    b.Add(c, 3);
                }
            }

            if (b.Coeffs[N] != 0)
                return null;

            // Fp(x) = [+-] x^(N-k) * b(x)
            IntegerPolynomial Fp = new IntegerPolynomial(N);
            int j = 0;
            k %= N;

            for (int i = N - 1; i >= 0; i--)
            {
                j = i - k;
                if (j < 0)
                    j += N;
                Fp.Coeffs[j] = f.Coeffs[0] * b.Coeffs[i];
            }

            Fp.EnsurePositive(3);

            return Fp;
        }

        /// <summary>
        /// Computes the inverse mod <c>q; q</c> must be a power of 2.
        /// <para>Returns <c>null</c> if the polynomial is not invertible.
        /// The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
        /// Almost Inverses and Fast NTRU Key Generation</a>.</para>
        /// </summary>
        /// 
        /// <param name="Q">The modulus</param>
        /// 
        /// <returns>A new polynomial, or <c>null</c> if no inverse exists</returns>
        public IntegerPolynomial InvertFq(int Q)
        {
            IntegerPolynomial Fq = InvertF2();
            if (Fq == null)
                return null;

            return Mod2ToModq(Fq, Q);
        }

        /// <summary>
        /// Tests if this polynomial is invertible modulo 2.
        /// <para>If a polynomial is invertible modulo 2, it is invertible modulo any power of 2.</para>
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if an inverse mod 2<sup>k</sup> for all k exists, <c>false</c> otherwise</returns>
        public bool IsInvertiblePow2()
        {
            return InvertF2() != null;
        }

        /// <summary>
        /// Tests whether all coefficients are between 0 and <c>modulus</c>
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        /// 
        /// <returns>Returns <c>true</c> if <c>0 &lt; c &lt; modulus</c> for all coefficients</returns>
        public bool IsReduced(int Modulus)
        {
            for (int i = 0; i < Coeffs.Length; i++)
            {
                if (Coeffs[i] < 0 || Coeffs[i] >= Modulus)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Tests id polynomial is ternary
        /// </summary>
        /// 
        /// <returns>True if ternary</returns>
        public bool IsTernary()
        {
            for (int i = 0; i < Coeffs.Length; i++)
            {
                if (Coeffs[i] < -1 || Coeffs[i] > 1)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Takes each coefficient modulo <c>modulus</c>.
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        public void Mod(int Modulus)
        {
            if (Modulus == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                    Coeffs[i] &= 2047;
            }
            else
            {
                for (int i = 0; i < Coeffs.Length; i++)
                    Coeffs[i] %= Modulus;
            }
        }

        /// <summary>
        /// Takes each coefficient modulo 3 such that all coefficients are ternary.
        /// </summary>
        public void Mod3()
        {
            for (int i = 0; i < Coeffs.Length; i++)
            {
                Coeffs[i] %= 3;

                if (Coeffs[i] > 1)
                    Coeffs[i] -= 3;
                if (Coeffs[i] < -1)
                    Coeffs[i] += 3;
            }
        }

        /// <summary>
        /// Reduces all coefficients to the interval [-modulus/2, modulus/2)
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        public void ModCenter(int Modulus)
        {
            if (Modulus == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                {
                    int c = Coeffs[i] & 2047;
                    if (c >= 1024)
                        c -= 2048;

                    Coeffs[i] = c;
                }
            }
            else
            {
                Mod(Modulus);

                for (int j = 0; j < Coeffs.Length; j++)
                {
                    while (Coeffs[j] < Modulus / 2)
                        Coeffs[j] += Modulus;
                    while (Coeffs[j] >= Modulus / 2)
                        Coeffs[j] -= Modulus;
                }
            }
        }

        /// <summary>
        /// Ensures all coefficients are between 0 and <c>modulus-1</c>
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        public void ModPositive(int Modulus)
        {
            if (Modulus == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                    Coeffs[i] &= 2047;
            }
            else
            {
                Mod(Modulus);
                EnsurePositive(Modulus);
            }
        }

        /// <summary>
        /// Ensures all coefficients are between 0 and 3
        /// </summary>
        public void ModPositive4()
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] &= 3;
        }

        /// <summary>
        /// Multiplies each coefficient by 3 and applies a modulus. Does not return a new polynomial but modifies this polynomial
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        public void Mult3(int Modulus)
        {
            if (Modulus == 2048)
            {
                for (int i = 0; i < Coeffs.Length; i++)
                    Coeffs[i] = (Coeffs[i] * 3) & 2047;
            }
            for (int i = 0; i < Coeffs.Length; i++)
            {
                Coeffs[i] *= 3;
                Coeffs[i] %= Modulus;
            }
        }

        /// <summary>
        /// Multiplies each coefficient by a <c>int</c>. Does not return a new polynomial but modifies this polynomial.
        /// </summary>
        /// 
        /// <param name="Factor">Integer factor</param>
        public void Multiply(int Factor)
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] *= Factor;
        }

        /// <summary>
        /// Multiplies the polynomial with another, taking the indices mod N
        /// </summary>
        /// <param name="Factor">The polynomial factor</param>
        /// 
        /// <returns>Multiplied polynomial</returns>
        public IntegerPolynomial Multiply(IntegerPolynomial Factor)
        {
            int N = Coeffs.Length;

            if (Factor.Coeffs.Length != N)
                throw new CryptoAsymmetricException("IntegerPolynomial:Multiply", "Number of coefficients must be the same!", new FormatException());

            IntegerPolynomial c = MultRecursive(Factor);

            if (c.Coeffs.Length > N)
            {
                for (int k = N; k < c.Coeffs.Length; k++)
                    c.Coeffs[k - N] += c.Coeffs[k];

                c.Coeffs = c.Coeffs.CopyOf(N);
            }

            return c;
        }

        /// <summary>
        /// Multiplies the polynomial with another, taking the indices mod N
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial factor</param>
        /// 
        /// <returns>Multiplied polynomial</returns>
        public BigIntPolynomial Multiply(BigIntPolynomial Factor)
        {
            return new BigIntPolynomial(this).MultSmall(Factor);
        }

        /// <summary>
        /// Multiplies the polynomial with another, taking the values mod modulus and the indices mod N
        /// </summary>
        /// 
        /// <param name="Factor">The polynomial factor</param>
        /// <param name="Modulus">The Modulus</param>
        /// 
        /// <returns>Multiplied polynomial</returns>
        public IntegerPolynomial Multiply(IntegerPolynomial Factor, int Modulus)
        {
            IntegerPolynomial c = Multiply(Factor);
            c.Mod(Modulus);

            return c;
        }

        /// <summary>
        /// Resultant of this polynomial with <c>x^n-1</c> using a probabilistic algorithm.
        /// </summary>
        /// 
        /// <remarks>
        /// <para>Unlike EESS, this implementation does not compute all resultants modulo primes
        /// such that their product exceeds the maximum possible resultant, but rather stops
        /// when <c>NUM_EQUAL_RESULTANTS</c> consecutive modular resultants are equal.
        /// This means the return value may be incorrect. Experiments show this happens in
        /// about 1 out of 100 cases when <c>N=439</c> and <c>NUM_EQUAL_RESULTANTS=2</c>,
        /// so the likelyhood of leaving the loop too early is <c>(1/100)^(NUM_EQUAL_RESULTANTS-1)</c>.</para>
        /// <para>Because of the above, callers must verify the output and try a different polynomial if necessary.</para>
        /// </remarks>
        /// 
        /// <returns>Returns <c>(rho, res)</c> satisfying <c>res = rho*this + t*(x^n-1)</c> for some integer <c>t</c>.</returns>
        public Resultant Resultant()
        {
            int N = Coeffs.Length;

            // Compute resultants modulo prime numbers. Continue until NUM_EQUAL_RESULTANTS consecutive modular resultants are equal.
            LinkedList<ModularResultant> modResultants = new LinkedList<ModularResultant>();
            BigInteger prime = null;
            BigInteger pProd = BigInteger.One;
            BigInteger pProd2 = null;
            BigInteger pProd2n = null;
            BigInteger res = BigInteger.One;
            int numEqual = 1;   // number of consecutive modular resultants equal to each other
            IEnumerator<BigInteger> primes = BIGINT_PRIMES.GetEnumerator();

            while (true)
            {
                if (!primes.MoveNext())
                    prime = prime.NextProbablePrime();
                else
                    prime = primes.Current;

                // prime = primes.hasNext() ? primes.next() : prime.NextProbablePrime();
                ModularResultant crr = Resultant(prime.ToInt32());
                modResultants.AddLast(crr);

                BigInteger temp = pProd.Multiply(prime);
                BigIntEuclidean er = BigIntEuclidean.Calculate(prime, pProd);
                BigInteger resPrev = res;
                res = res.Multiply(er.X.Multiply(prime));

                BigInteger res2 = crr.Res.Multiply(er.Y.Multiply(pProd));
                res = res.Add(res2).Mod(temp);
                pProd = temp;
                pProd2 = pProd.ShiftRight(1);
                pProd2n = pProd2.Negate();

                if (res.CompareTo(pProd2) > 0)
                    res = res.Subtract(pProd);
                else if (res.CompareTo(pProd2n) < 0)
                    res = res.Add(pProd);

                if (res.Equals(resPrev))
                {
                    numEqual++;

                    if (numEqual >= NUM_EQUAL_RESULTANTS)
                        break;
                }
                else
                {
                    numEqual = 1;
                }
            }

            // Combine modular rho's to obtain the rho.
            // For efficiency, first combine all pairs of small resultants to bigger resultants,
            // then combine pairs of those, etc. until only one is left.
            while (modResultants.Count > 1)
            {
                ModularResultant modRes1 = modResultants.First.Value;
                modResultants.RemoveFirst();
                ModularResultant modRes2 = modResultants.First.Value;
                modResultants.RemoveFirst();
                ModularResultant modRes3 = ModularResultant.CombineRho(modRes1, modRes2);
                modResultants.AddLast(modRes3);
            }

            BigIntPolynomial rhoP = modResultants.First.Value.Rho;

            if (res.CompareTo(pProd2) > 0)
                res = res.Subtract(pProd);
            if (res.CompareTo(pProd2n) < 0)
                res = res.Add(pProd);

            for (int i = 0; i < N; i++)
            {
                BigInteger c = rhoP.Coeffs[i];

                if (c.CompareTo(pProd2) > 0)
                    rhoP.Coeffs[i] = c.Subtract(pProd);
                if (c.CompareTo(pProd2n) < 0)
                    rhoP.Coeffs[i] = c.Add(pProd);
            }

            return new Resultant(rhoP, res);
        }

        /// <summary>
        /// Multiplication by <c>X</c> in <c>Z[X]/Z[X^n-1]</c>.
        /// </summary>
        public void Rotate1()
        {
            int clast = Coeffs[Coeffs.Length - 1];
            for (int i = Coeffs.Length - 1; i > 0; i--)
                Coeffs[i] = Coeffs[i - 1];

            Coeffs[0] = clast;
        }

        /// <summary>
        /// Subtracts another polynomial which must not have more coefficients than <c>this</c> polynomial.
        /// </summary>
        /// 
        /// <param name="B">The polynomial to subtract</param>
        public void Subtract(IntegerPolynomial B)
        {
            for (int i = 0; i < B.Coeffs.Length; i++)
                Coeffs[i] -= B.Coeffs[i];
        }

        /// <summary>
        /// Resultant of this polynomial with <c>x^n-1 mod p</c>.
        /// </summary>
        /// 
        /// <param name="P">P value</param>
        /// 
        /// <returns>Returns <c>(rho, res)</c> satisfying <c>res = rho*this + t*(x^n-1) mod p</c> for some integer <c>t</c>.</returns>
        public ModularResultant Resultant(int P)
        {
            // Add a coefficient as the following operations involve polynomials of degree deg(f)+1
            int[] fcoeffs = Coeffs.CopyOf(Coeffs.Length + 1);
            IntegerPolynomial f = new IntegerPolynomial(fcoeffs);
            int N = fcoeffs.Length;

            IntegerPolynomial a = new IntegerPolynomial(N);
            a.Coeffs[0] = -1;
            a.Coeffs[N - 1] = 1;
            IntegerPolynomial b = new IntegerPolynomial(f.Coeffs);
            IntegerPolynomial v1 = new IntegerPolynomial(N);
            IntegerPolynomial v2 = new IntegerPolynomial(N);
            v2.Coeffs[0] = 1;
            int da = N - 1;
            int db = b.Degree();
            int ta = da;
            int c = 0;
            int r = 1;

            while (db > 0)
            {
                c = Invert(b.Coeffs[db], P);
                c = (c * a.Coeffs[da]) % P;
                a.MultShiftSub(b, c, da - db, P);
                v1.MultShiftSub(v2, c, da - db, P);
                da = a.Degree();

                if (da < db)
                {
                    r *= Pow(b.Coeffs[db], ta - da, P);
                    r %= P;

                    if (ta % 2 == 1 && db % 2 == 1)
                        r = (-r) % P;

                    IntegerPolynomial temp = a;
                    a = b;
                    b = temp;
                    int tempdeg = da;
                    da = db;
                    temp = v1;
                    v1 = v2;
                    v2 = temp;
                    ta = db;
                    db = tempdeg;
                }
            }

            r *= Pow(b.Coeffs[0], da, P);
            r %= P;
            c = Invert(b.Coeffs[0], P);
            v2.Multiply(c);
            v2.Mod(P);
            v2.Multiply(r);
            v2.Mod(P);

            // drop the highest coefficient so #coeffs matches the original input
            v2.Coeffs = v2.Coeffs.CopyOf(v2.Coeffs.Length - 1);
            return new ModularResultant(new BigIntPolynomial(v2), BigInteger.ValueOf(r), BigInteger.ValueOf(P));
        }

        /// <summary>
        /// Returns the sum of all coefficients, i.e. evaluates the polynomial at 1.
        /// </summary>
        /// 
        /// <returns>The sum of all coefficients</returns>
        public int SumCoeffs()
        {
            int sum = 0;

            for (int i = 0; i < Coeffs.Length; i++)
                sum += Coeffs[i];

            return sum;
        }

        /// <summary>
        /// Encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
        /// </summary>
        /// 
        /// <param name="Q">Q value</param>
        /// 
        /// <returns>The encoded polynomial</returns>
        public byte[] ToBinary(int Q)
        {
            return ArrayEncoder.EncodeModQ(Coeffs, Q);
        }

        /// <summary>
        /// Encodes a polynomial with ternary coefficients to binary.
        /// <para><c>coeffs[2*i]</c> and <c>coeffs[2*i+1]</c> must not both equal -1 for any integer <c>i</c>,
        /// so this method is only safe to use with polynomials produced by <c>fromBinary3Sves()</c>.</para>
        /// </summary>
        /// 
        /// <param name="SkipFirst">Whether to skip the constant coefficient</param>
        /// 
        /// <returns>The encoded polynomial</returns>
        public byte[] ToBinary3Sves(bool SkipFirst)
        {
            return ArrayEncoder.EncodeMod3Sves(Coeffs, SkipFirst);
        }

        /// <summary>
        /// Converts a polynomial with ternary coefficients to binary.
        /// </summary>
        /// 
        /// <returns>The encoded polynomial</returns>
        public byte[] ToBinary3Tight()
        {
            return ArrayEncoder.EncodeMod3Tight(Coeffs);
        }

        /// <summary>
        /// Like ToBinary(int) but only returns the first <c>numBytes</c> bytes of the encoding.
        /// </summary>
        /// 
        /// <param name="Q">Q value</param>
        /// <param name="NumBytes">Byte count</param>
        /// 
        /// <returns>The encoded polynomial</returns>
        public byte[] ToBinaryTrunc(int Q, int NumBytes)
        {
            return ArrayEncoder.EncodeModQTrunc(Coeffs, Q, NumBytes);
        }

        /// <summary>
        /// Optimized version of ToBinary(int) for <c>q=4</c>.
        /// <para>Encodes the low 2 bits of all coefficients in a byte array.</para>
        /// </summary>
        /// 
        /// <returns>A byte array equal to what <c>toBinary(4)</c> would return</returns>
        public byte[] ToBinary4()
        {
            byte[] data = new byte[(Coeffs.Length + 3) / 4];
            int i = 0;

            while (i < Coeffs.Length - 3)
            {
                int c0 = Coeffs[i] & 3;
                int c1 = Coeffs[i + 1] & 3;
                int c2 = Coeffs[i + 2] & 3;
                int c3 = Coeffs[i + 3] & 3;
                int d = c0 + (c1 << 2) + (c2 << 4) + (c3 << 6);
                data[i / 4] = (byte)d;
                i += 4;
            }

            // handle the last 0 to 3 coefficients
            if (i >= Coeffs.Length)
                return data;
            int last = data.Length - 1;
            data[last] = (byte)(Coeffs[i] & 3);
            i++;

            if (i >= Coeffs.Length)
                return data;
            data[last] |= (byte)((Coeffs[i] & 3) << 2);
            i++;

            if (i >= Coeffs.Length)
                return data;
            data[last] |= (byte)((Coeffs[i] & 3) << 4);
            i++;

            if (i >= Coeffs.Length)
                return data;
            data[last] |= (byte)((Coeffs[i] & 3) << 6);

            return data;
        }

        /// <summary>
        /// Returns a polynomial that is equal to this polynomial (in the sense that mult(IntegerPolynomial, int) 
        /// returns equal <c>IntegerPolynomial</c>s). The new polynomial is guaranteed to be independent of the original.
        /// </summary>
        /// 
        /// <returns>The polynomial product</returns>
        public IntegerPolynomial ToIntegerPolynomial()
        {
            return Clone();
        }
        #endregion

        #region Private Methods
        private IntegerPolynomial MultRecursive(IntegerPolynomial Factor)
        {
            int[] a = Coeffs;
            int[] b = Factor.Coeffs;
            int n = Factor.Coeffs.Length;

            if (n <= 32)
            {
                int cn = 2 * n - 1;
                IntegerPolynomial c = new IntegerPolynomial(new int[cn]);

                for (int k = 0; k < cn; k++)
                {
                    for (int i = Math.Max(0, k - n + 1); i <= Math.Min(k, n - 1); i++)
                        c.Coeffs[k] += b[i] * a[k - i];
                }

                return c;
            }
            else
            {
                int n1 = n / 2;

                IntegerPolynomial a1 = new IntegerPolynomial(a.CopyOf(n1));
                IntegerPolynomial a2 = new IntegerPolynomial(a.CopyOfRange(n1, n));
                IntegerPolynomial b1 = new IntegerPolynomial(b.CopyOf(n1));
                IntegerPolynomial b2 = new IntegerPolynomial(b.CopyOfRange(n1, n));

                // make a copy of a1 that is the same length as a2
                IntegerPolynomial A = new IntegerPolynomial(a1.Coeffs.CopyOf(a2.Coeffs.Length));
                A.Add(a2);
                // make a copy of b1 that is the same length as b2
                IntegerPolynomial B = new IntegerPolynomial(b1.Coeffs.CopyOf(b2.Coeffs.Length));
                B.Add(b2);

                IntegerPolynomial c1 = a1.MultRecursive(b1);
                IntegerPolynomial c2 = a2.MultRecursive(b2);
                IntegerPolynomial c3 = A.MultRecursive(B);
                c3.Subtract(c1);
                c3.Subtract(c2);

                IntegerPolynomial c = new IntegerPolynomial(2 * n - 1);
                for (int i = 0; i < c1.Coeffs.Length; i++)
                    c.Coeffs[i] = c1.Coeffs[i];
                for (int i = 0; i < c3.Coeffs.Length; i++)
                    c.Coeffs[n1 + i] += c3.Coeffs[i];
                for (int i = 0; i < c2.Coeffs.Length; i++)
                    c.Coeffs[2 * n1 + i] += c2.Coeffs[i];

                return c;
            }
        }

        /// <summary>
        /// Computes the inverse mod 2. 
        /// <para>The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
        /// Almost Inverses and Fast NTRU Key Generation</a>.</para>
        /// </summary>
        /// 
        /// <returns>Returns <c>null</c> if the polynomial is not invertible.</returns>
        private IntegerPolynomial InvertF2()
        {
            int N = Coeffs.Length;
            int k = 0;
            IntegerPolynomial b = new IntegerPolynomial(N + 1);
            b.Coeffs[0] = 1;

            IntegerPolynomial c = new IntegerPolynomial(N + 1);
            IntegerPolynomial f = new IntegerPolynomial(Coeffs.CopyOf(N + 1));
            f.Mod2();

            // set g(x) = x^N − 1
            IntegerPolynomial g = new IntegerPolynomial(N + 1);
            g.Coeffs[0] = 1;
            g.Coeffs[N] = 1;

            while (true)
            {
                while (f.Coeffs[0] == 0)
                {
                    for (int i = 1; i <= N; i++)
                    {
                        f.Coeffs[i - 1] = f.Coeffs[i];          // f(x) = f(x) / x
                        c.Coeffs[N + 1 - i] = c.Coeffs[N - i];  // c(x) = c(x) * x
                    }

                    f.Coeffs[N] = 0;
                    c.Coeffs[0] = 0;
                    k++;

                    if (f.EqualsZero())
                        return null;    // not invertible
                }

                if (f.EqualsOne())
                    break;

                if (f.Degree() < g.Degree())
                {
                    // exchange f and g
                    IntegerPolynomial temp = f;
                    f = g;
                    g = temp;
                    // exchange b and c
                    temp = b;
                    b = c;
                    c = temp;
                }

                f.Add(g);
                f.Mod2();
                b.Add(c);
                b.Mod2();
            }

            if (b.Coeffs[N] != 0)
                return null;

            // Fq(x) = x^(N-k) * b(x)
            IntegerPolynomial Fq = new IntegerPolynomial(N);
            int j = 0;
            k %= N;

            for (int i = N - 1; i >= 0; i--)
            {
                j = i - k;
                if (j < 0)
                    j += N;
                Fq.Coeffs[j] = b.Coeffs[i];
            }

            return Fq;
        }

        /// <summary>
        /// Computes the inverse mod <c>q</c> from the inverse mod 2.
        /// <para>The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
        /// Almost Inverses and Fast NTRU Key Generation</a>.</para>
        /// </summary>
        /// 
        /// <param name="Fq">Fq value</param>
        /// <param name="Q">Q value</param>
        /// 
        /// <returns>The inverse of this polynomial mod q</returns>
        private IntegerPolynomial Mod2ToModq(IntegerPolynomial Fq, int Q)
        {
            if (SystemUtils.Is64Bit() && Q == 2048)
            {
                LongPolynomial2 thisLong = new LongPolynomial2(this);
                LongPolynomial2 FqLong = new LongPolynomial2(Fq);
                int v = 2;
                while (v < Q)
                {
                    v *= 2;
                    LongPolynomial2 temp = FqLong.Clone();
                    temp.Mult2And(v - 1);
                    FqLong = thisLong.Multiply(FqLong).Multiply(FqLong);
                    temp.SubAnd(FqLong, v - 1);
                    FqLong = temp;
                }
                return FqLong.ToIntegerPolynomial();
            }
            else
            {
                int v = 2;
                while (v < Q)
                {
                    v *= 2;
                    IntegerPolynomial temp = Fq.Clone();
                    temp.Mult2(v);
                    Fq = Multiply(Fq, v).Multiply(Fq, v);
                    temp.Subtract(Fq, v);
                    Fq = temp;
                }
                return Fq;
            }
        }

        /// <remarks>
        /// Calculates the inverse of n mod modulus
        /// </remarks>
        private int Invert(int n, int modulus)
        {
            n %= modulus;
            if (n < 0)
                n += modulus;

            return IntEuclidean.Calculate(n, modulus).X;
        }

        /// <remarks>
        /// Calculates a^b mod modulus
        /// </remarks>
        private int Pow(int A, int B, int Modulus)
        {
            int p = 1;

            for (int i = 0; i < B; i++)
                p = (p * A) % Modulus;

            return p;
        }

        /// <remarks>
        ///  Computes this-b*c*(x^k) mod p and stores the result in this polynomial.
        /// </remarks>
        private void MultShiftSub(IntegerPolynomial B, int C, int K, int P)
        {
            int N = Coeffs.Length;

            for (int i = K; i < N; i++)
                Coeffs[i] = (Coeffs[i] - B.Coeffs[i - K] * C) % P;
        }

        /// <remarks>
        /// Returns the degree of the polynomial
        /// </remarks>
        private int Degree()
        {
            int degree = Coeffs.Length - 1;

            while (degree > 0 && Coeffs[degree] == 0)
                degree--;

            return degree;
        }

        /// <summary>
        /// Subtracts another polynomial which can have a different number of coefficients,
        /// and takes the coefficient values mod <c>modulus</c>.
        /// </summary>
        /// 
        /// <param name="B">The polynomial to subtract</param>
        /// <param name="Modulus">The modulus</param>
        private void Subtract(IntegerPolynomial B, int Modulus)
        {
            Subtract(B);
            Mod(Modulus);
        }

        /// <summary>
        /// Subtracts a <c>int</c> from each coefficient. Does not return a new polynomial but modifies this polynomial.
        /// </summary>
        /// 
        /// <param name="B">A number to subtract from each coefficient</param>
        private void Subtract(int B)
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] -= B;
        }

        /// <summary>
        /// Multiplies each coefficient by 2 and applies a modulus. Does not return a new polynomial but modifies this polynomial
        /// </summary>
        /// 
        /// <param name="Modulus">The Modulus</param>
        private void Mult2(int Modulus)
        {
            for (int i = 0; i < Coeffs.Length; i++)
            {
                Coeffs[i] *= 2;
                Coeffs[i] %= Modulus;
            }
        }

        /// <summary>
        /// Optimized version of ModPositive(2) //p
        /// </summary>
        private void Mod2()
        {
            for (int i = 0; i < Coeffs.Length; i++)
                Coeffs[i] &= 1;
        }

        /// <summary>
        /// Shifts all coefficients so the largest gap is centered around <c>-q/2</c>.
        /// </summary>
        /// 
        /// <param name="Q">The Modulus</param>
        private void ShiftGap(int Q)
        {
            ModCenter(Q);

            int[] sorted = (int[])Coeffs.Clone();
            Array.Sort(sorted);
            int maxrange = 0;
            int maxrangeStart = 0;

            for (int i = 0; i < sorted.Length - 1; i++)
            {
                int range = sorted[i + 1] - sorted[i];
                if (range > maxrange)
                {
                    maxrange = range;
                    maxrangeStart = sorted[i];
                }
            }

            int pmin = sorted[0];
            int pmax = sorted[sorted.Length - 1];
            int j = Q - pmax + pmin;
            int shift;

            if (j > maxrange)
                shift = (pmax + pmin) / 2;
            else
                shift = maxrangeStart + maxrange / 2 + Q / 2;

            Subtract(shift);
        }

        /// <summary>
        /// Tests if <c>p(x) = 0</c>.
        /// </summary>
        /// 
        /// <returns>True if all coefficients are zeros</returns>
        private bool EqualsZero()
        {
            for (int i = 0; i < Coeffs.Length; i++)
            {
                if (Coeffs[i] != 0)
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Tests if <c>|p(x)| = 1</c>.
        /// </summary>
        /// 
        /// <returns>True iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 or -1</returns>
        private bool EqualsAbsOne()
        {
            for (int i = 1; i < Coeffs.Length; i++)
            {
                if (Coeffs[i] != 0)
                    return false;
            }

            return Math.Abs(Coeffs[0]) == 1;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return ArrayUtils.GetHashCode(Coeffs);
        }

        /// <summary>
        /// Compare this integer polynomial to another for equality
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj.GetType().IsAssignableFrom(typeof(IntegerPolynomial)))
                return Compare.IsEqual(Coeffs, ((IntegerPolynomial)Obj).Coeffs);
            else
                return false;
        }
        #endregion
    }
}