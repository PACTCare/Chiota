#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class stores very long strings of bits and does some basic arithmetics.
    /// <para>It is used by <c>GF2nField</c>, <c>GF2nPolynomialField</c> and <c>GFnPolynomialElement</c>.</para>
    /// </summary>
    internal sealed class GF2Polynomial
    {
        #region Fields
        // number of bits stored in this GF2Polynomial
        private int m_length;
        // number of int used in value
        private int m_blocks;
        // storage
        private int[] m_value;
        // Random source
        private static Random m_rand = new Random();

        // Lookup-Table for vectorMult: parity[a]= #1(a) mod 2 == 1
        private static readonly bool[] m_parity = 
        {
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            true, false, false, true, false, true, true, false, false, true, true, false, true, false, false, true, 
            false, true, true, false, true, false, false, true, true, false, false, true, false, true, true, false
        };

        // Lookup-Table for Squaring: squaringTable[a]=a^2
        private static readonly short[] m_squaringTable = 
        {
            0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015, 0x0040, 0x0041, 0x0044, 0x0045, 
            0x0050, 0x0051, 0x0054, 0x0055, 0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115, 
            0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155, 0x0400, 0x0401, 0x0404, 0x0405, 
            0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455, 
            0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515, 0x0540, 0x0541, 0x0544, 0x0545, 
            0x0550, 0x0551, 0x0554, 0x0555, 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015, 
            0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055, 0x1100, 0x1101, 0x1104, 0x1105, 
            0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155, 
            0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440, 0x1441, 0x1444, 0x1445, 
            0x1450, 0x1451, 0x1454, 0x1455, 0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515, 
            0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555, 0x4000, 0x4001, 0x4004, 0x4005, 
            0x4010, 0x4011, 0x4014, 0x4015, 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055, 
            0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140, 0x4141, 0x4144, 0x4145, 
            0x4150, 0x4151, 0x4154, 0x4155, 0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415, 
            0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455, 0x4500, 0x4501, 0x4504, 0x4505, 
            0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555, 
            0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015, 0x5040, 0x5041, 0x5044, 0x5045, 
            0x5050, 0x5051, 0x5054, 0x5055, 0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115, 
            0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155, 0x5400, 0x5401, 0x5404, 0x5405, 
            0x5410, 0x5411, 0x5414, 0x5415, 0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455, 
            0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544, 0x5545, 
            0x5550, 0x5551, 0x5554, 0x5555
        };

        // pre-computed Bitmask for fast masking, bitMask[a]=0x1 << a
        private static readonly int[] m_bitMask = 
        {
            0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 
            0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 
            0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 
            0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 
            0x10000000, 0x20000000, 0x40000000, unchecked((int)0x80000000), 0x00000000
        };

        // pre-computed Bitmask for fast masking, rightMask[a]=0xffffffff >>> (32-a)
        private static readonly int[] m_reverseRightMask = 
        {
            0x00000000, 0x00000001, 0x00000003, 0x00000007, 0x0000000f, 0x0000001f, 0x0000003f,
            0x0000007f, 0x000000ff, 0x000001ff, 0x000003ff, 0x000007ff, 0x00000fff, 0x00001fff, 
            0x00003fff, 0x00007fff, 0x0000ffff, 0x0001ffff, 0x0003ffff, 0x0007ffff, 0x000fffff, 
            0x001fffff, 0x003fffff, 0x007fffff, 0x00ffffff, 0x01ffffff, 0x03ffffff, 0x07ffffff, 
            0x0fffffff, 0x1fffffff, 0x3fffffff, 0x7fffffff, unchecked((int)0xffffffff)
        };
        #endregion

        #region Properties
        /// <summary>
        /// Returns the length of this GF2Polynomial. The length can be greater than the degree.
        /// To get the degree call ReduceN() before calling Length property.
        /// </summary>
        public int Length
        {
            get { return m_length; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Creates a new GF2Polynomial of the given <c>Length</c> and value zero
        /// </summary>
        /// 
        /// <param name="Length">The desired number of bits to store</param>
        public GF2Polynomial(int Length)
        {
            int l = Length;
            if (l < 1)
                l = 1;
            
            m_blocks = ((l - 1) >> 5) + 1;
            m_value = new int[m_blocks];
            m_length = l;
        }

        /// <summary>
        /// Creates a new GF2Polynomial of the given <c>Length</c> and random value
        /// </summary>
        /// 
        /// <param name="Length">The desired number of bits to store</param>
        /// <param name="Rand">The Random instance to use for randomization</param>
        public GF2Polynomial(int Length, Random Rand)
        {
            int l = Length;
            if (l < 1)
                l = 1;
            
            m_blocks = ((l - 1) >> 5) + 1;
            m_value = new int[m_blocks];
            m_length = l;
            Randomize(Rand);
        }

        /// <summary>
        /// Creates a new GF2Polynomial of the given <c>Length</c> and value selected by <c>Value</c>
        /// <para>Values are: ZERO, ONE, RANDOM, X and ALL</para>
        /// </summary>
        /// 
        /// <param name="Length">The desired number of bits to store</param>
        /// <param name="Value">The value described by a String</param>
        public GF2Polynomial(int Length, String Value)
        {
            int l = Length;
            if (l < 1)
                l = 1;

            m_blocks = ((l - 1) >> 5) + 1;
            m_value = new int[m_blocks];
            m_length = l;

            if (Value.ToUpper().Equals("ZERO"))
                AssignZero();
            else if (Value.ToUpper().Equals("ONE"))
                AssignOne();
            else if (Value.ToUpper().Equals("RANDOM"))
                Randomize();
            else if (Value.ToUpper().Equals("X"))
                AssignX();
            else if (Value.ToUpper().Equals("ALL"))
                AssignAll();
            else
                throw new ArgumentException("Error: GF2Polynomial was called using " + Value + " as value!");
        }

        /// <summary>
        /// Creates a new GF2Polynomial of the given <c>Length</c> using the given int[]. LSB is contained in bs[0].
        /// </summary>
        /// 
        /// <param name="Length">The desired number of bits to store</param>
        /// <param name="Bs">Contains the desired value, LSB in bs[0]</param>
        public GF2Polynomial(int Length, int[] Bs)
        {
            int leng = Length;
            if (leng < 1)
                leng = 1;
            
            m_blocks = ((leng - 1) >> 5) + 1;
            m_value = new int[m_blocks];
            m_length = leng;
            int l = Math.Min(m_blocks, Bs.Length);
            Array.Copy(Bs, 0, m_value, 0, l);
            ZeroUnusedBits();
        }

        /// <summary>
        /// Creates a new GF2Polynomial by converting the given byte[] <c>Os</c> according to 1363 and using the given <c>Length</c>
        /// </summary>
        /// 
        /// <param name="Length">The intended length of this polynomial</param>
        /// <param name="Os">The octet string to assign to this polynomial</param>
        public GF2Polynomial(int Length, byte[] Os)
        {
            int l = Length;
            if (l < 1)
                l = 1;
            
            m_blocks = ((l - 1) >> 5) + 1;
            m_value = new int[m_blocks];
            m_length = l;
            int i, m;
            int k = Math.Min(((Os.Length - 1) >> 2) + 1, m_blocks);
            for (i = 0; i < k - 1; i++)
            {
                m = Os.Length - (i << 2) - 1;
                m_value[i] = (int)((Os[m]) & 0x000000ff);
                m_value[i] |= (int)((Os[m - 1] << 8) & 0x0000ff00);
                m_value[i] |= (int)((Os[m - 2] << 16) & 0x00ff0000);
                m_value[i] |= (int)((Os[m - 3] << 24) & 0xff000000);
            }

            i = k - 1;
            m = Os.Length - (i << 2) - 1;
            m_value[i] = Os[m] & 0x000000ff;
            if (m > 0)
                m_value[i] |= (Os[m - 1] << 8) & 0x0000ff00;
            if (m > 1)
                m_value[i] |= (Os[m - 2] << 16) & 0x00ff0000;
            if (m > 2)
                m_value[i] |= (int)((Os[m - 3] << 24) & 0xff000000);
            
            ZeroUnusedBits();
            ReduceN();
        }

        /// <summary>
        /// Creates a new GF2Polynomial by converting the given FlexiBigInt <c>Bi</c> according to 1363 and using the given <c>Length</c>
        /// </summary>
        /// 
        /// <param name="Length">The intended length of this polynomial</param>
        /// <param name="Bi">The FlexiBigInt to assign to this polynomial</param>
        public GF2Polynomial(int Length, BigInteger Bi)
        {
            int l = Length;
            if (l < 1)
                l = 1;
            
            m_blocks = ((l - 1) >> 5) + 1;
            m_value = new int[m_blocks];
            m_length = l;
            int i;
            byte[] val = Bi.ToByteArray();

            if (val[0] == 0)
            {
                byte[] dummy = new byte[val.Length - 1];
                Array.Copy(val, 1, dummy, 0, dummy.Length);
                val = dummy;
            }

            int ov = val.Length & 0x03;
            int k = ((val.Length - 1) >> 2) + 1;
            for (i = 0; i < ov; i++)
            {
                m_value[k - 1] |= (val[i] & 0x000000ff) << ((ov - 1 - i) << 3);
            }

            int m = 0;
            for (i = 0; i <= (val.Length - 4) >> 2; i++)
            {
                m = val.Length - 1 - (i << 2);
                m_value[i] = (int)((val[m]) & 0x000000ff);
                m_value[i] |= (int)(((val[m - 1]) << 8) & 0x0000ff00);
                m_value[i] |= (int)(((val[m - 2]) << 16) & 0x00ff0000);
                m_value[i] |= (int)(((val[m - 3]) << 24) & 0xff000000);
            }

            if ((m_length & 0x1f) != 0)
                m_value[m_blocks - 1] &= m_reverseRightMask[m_length & 0x1f];

            ReduceN();
        }

        /// <summary>
        /// Creates a new GF2Polynomial by cloneing the given GF2Polynomial <c>B</c>
        /// </summary>
        /// 
        /// <param name="B">The GF2Polynomial to clone</param>
        public GF2Polynomial(GF2Polynomial B)
        {
            m_length = B.m_length;
            m_blocks = B.m_blocks;
            m_value = IntUtils.DeepCopy(B.m_value);
        }
        #endregion

        #region Conversions
        /// <summary>
        /// Converts this polynomial to a byte[] (octet string) according to 1363
        /// </summary>
        /// 
        /// <returns>Return a byte[] representing the value of this polynomial</returns>
        public byte[] ToByteArray()
        {
            int k = ((m_length - 1) >> 3) + 1;
            int ov = k & 0x03;
            int m;
            byte[] res = new byte[k];
            int i;

            for (i = 0; i < (k >> 2); i++)
            {
                m = k - (i << 2) - 1;
                res[m] = (byte)((m_value[i] & 0x000000ff));
                res[m - 1] = (byte)(IntUtils.URShift((m_value[i] & 0x0000ff00), 8));
                res[m - 2] = (byte)(IntUtils.URShift((m_value[i] & 0x00ff0000), 16));
                res[m - 3] = (byte)(IntUtils.URShift((m_value[i] & 0xff000000), 24));
            }
            for (i = 0; i < ov; i++)
            {
                m = (ov - i - 1) << 3;
                res[i] = (byte)(IntUtils.URShift((m_value[m_blocks - 1] & (0x000000ff << m)), m));
            }

            return res;
        }

        /// <summary>
        /// Converts this polynomial to an integer according to 1363
        /// </summary>
        /// 
        /// <returns>Returns a FlexiBigInt representing the value of this polynomial</returns>
        public BigInteger ToFlexiBigInt()
        {
            if (m_length == 0 || IsZero())
                return new BigInteger(0, new byte[0]);
            
            return new BigInteger(1, ToByteArray());
        }

        /// <summary>
        /// Returns the value of this GF2Polynomial in an integer array
        /// </summary>
        /// 
        /// <returns>Returns the value of this GF2Polynomial in a new int[], LSB in int[0]</returns>
        public int[] ToIntegerArray()
        {
            int[] result;
            result = new int[m_blocks];
            Array.Copy(m_value, 0, result, 0, m_blocks);

            return result;
        }

        /// <summary>
        /// Returns a string representing this GF2Polynomials value using hexadecimal or binary radix in MSB-first order
        /// </summary>
        /// 
        /// <param name="Radix">The radix to use (2 or 16, otherwise 2 is used)</param>
        /// 
        /// <returns>Returns a String representing this GF2Polynomials value</returns>
        public String ToString(int Radix)
        {
            char[] HEX_CHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
            String[] BIN_CHARS = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };
            String res = "";
            int i;

            if (Radix == 16)
            {
                for (i = m_blocks - 1; i >= 0; i--)
                {
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 28)) & 0x0f];
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 24)) & 0x0f];
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 20)) & 0x0f];
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 16)) & 0x0f];
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 12)) & 0x0f];
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 8)) & 0x0f];
                    res += HEX_CHARS[(IntUtils.URShift(m_value[i], 4)) & 0x0f];
                    res += HEX_CHARS[(m_value[i]) & 0x0f];
                    res += " ";
                }
            }
            else
            {
                for (i = m_blocks - 1; i >= 0; i--)
                {
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 28)) & 0x0f];
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 24)) & 0x0f];
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 20)) & 0x0f];
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 16)) & 0x0f];
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 12)) & 0x0f];
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 8)) & 0x0f];
                    res += BIN_CHARS[(IntUtils.URShift(m_value[i], 4)) & 0x0f];
                    res += BIN_CHARS[(m_value[i]) & 0x0f];
                    res += " ";
                }
            }
            return res;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds two GF2Polynomials, <c>this</c> and <c>B</c>, and returns the result. 
        /// <c>this</c> and <c>B</c> can be of different size.
        /// </summary>
        /// 
        /// <param name="B">A GF2Polynomial</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (<c>this</c> + <c>B</c>)</returns>
        public GF2Polynomial Add(GF2Polynomial B)
        {
            return Xor(B);
        }

        /// <summary>
        /// Adds <c>B</c> to this GF2Polynomial and assigns the result to this GF2Polynomial. 
        /// <c>B</c> can be of different size.
        /// </summary>
        /// 
        /// <param name="B">GF2Polynomial to add to this GF2Polynomial</param>
        public void AddToThis(GF2Polynomial B)
        {
            ExpandN(B.m_length);
            XorThisBy(B);
        }

        /// <summary>
        /// Sets all Bits to 1
        /// </summary>
        public void AssignAll()
        {
            for (int i = 0; i < m_blocks; i++)
                m_value[i] = unchecked((int)0xffffffff);
            
            ZeroUnusedBits();
        }

        /// <summary>
        /// Sets the LSB to 1 and all other to 0, assigning 'one' to this GF2Polynomial
        /// </summary>
        public void AssignOne()
        {
            for (int i = 1; i < m_blocks; i++)
                m_value[i] = 0x00;
            
            m_value[0] = 0x01;
        }

        /// <summary>
        /// Sets Bit 1 to 1 and all other to 0, assigning 'x' to this GF2Polynomial
        /// </summary>
        public void AssignX()
        {
            for (int i = 1; i < m_blocks; i++)
                m_value[i] = 0x00;
            
            m_value[0] = 0x02;
        }

        /// <summary>
        /// Resets all bits to zero
        /// </summary>
        public void AssignZero()
        {
            for (int i = 0; i < m_blocks; i++)
                m_value[i] = 0x00;
        }

        /// <summary>
        /// Return a copy of this GF2Polynomial
        /// </summary>
        /// 
        /// <returns>Returns a copy of <c>this</c></returns>
        public Object Clone()
        {
            return new GF2Polynomial(this);
        }

        /// <summary>
        /// Divides <c>this</c> by <c>G</c> and returns the quotient and remainder in a new GF2Polynomial[2], quotient in [0], remainder in [1]
        /// </summary>
        /// 
        /// <param name="G">A GF2Polynomial != 0</param>
        /// 
        /// <returns>Returns a new GF2Polynomial[2] containing quotient and remainder</returns>
        public GF2Polynomial[] Divide(GF2Polynomial G)
        {
            // a div b = q / r
            GF2Polynomial[] result = new GF2Polynomial[2];
            GF2Polynomial q = new GF2Polynomial(m_length);
            GF2Polynomial a = new GF2Polynomial(this);
            GF2Polynomial b = new GF2Polynomial(G);
            GF2Polynomial j;
            int i;

            if (b.IsZero())
                throw new Exception();
            
            a.ReduceN();
            b.ReduceN();

            if (a.m_length < b.m_length)
            {
                result[0] = new GF2Polynomial(0);
                result[1] = a;
                return result;
            }

            i = a.m_length - b.m_length;
            q.ExpandN(i + 1);

            while (i >= 0)
            {
                j = b.ShiftLeft(i);
                a.SubtractFromThis(j);
                a.ReduceN();
                q.XorBit(i);
                i = a.m_length - b.m_length;
            }

            result[0] = q;
            result[1] = a;

            return result;
        }

        /// <summary>
        /// Expands len and int[] value to <c>I</c>. This is useful before adding two GF2Polynomials of different size
        /// </summary>
        /// 
        /// <param name="I">The intended length</param>
        public void ExpandN(int I)
        {
            int k;
            int[] bs;
            if (m_length >= I)
                return;

            m_length = I;
            k = (IntUtils.URShift((I - 1), 5)) + 1;

            if (m_blocks >= k)
                return;

            if (m_value.Length >= k)
            {
                int j;
                for (j = m_blocks; j < k; j++)
                    m_value[j] = 0;

                m_blocks = k;
                return;
            }

            bs = new int[k];
            Array.Copy(m_value, 0, bs, 0, m_blocks);
            m_blocks = k;
            m_value = null;
            m_value = bs;
        }

        /// <summary>
        /// Returns the bit at position <c>Index</c>
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        /// 
        /// <returns>Returns the bit at position <c>Index</c> if <c>Index</c> is a valid position, 0 otherwise</returns>
        public int GetBit(int Index)
        {
            if (Index < 0 || Index > (m_length - 1))
                return 0;

            return ((m_value[IntUtils.URShift(Index, 5)] & m_bitMask[Index & 0x1f]) != 0) ? 1 : 0;
        }

        /// <summary>
        /// Returns the greatest common divisor of <c>this</c> and <c>G</c> in a new GF2Polynomial
        /// </summary>
        /// 
        /// <param name="G">A GF2Polynomial != 0</param>
        /// 
        /// <returns>Returns a new GF2Polynomial gcd(<c>this</c>,<c>g</c>)</returns>
        public GF2Polynomial Gcd(GF2Polynomial G)
        {
            if (IsZero() && G.IsZero())
                throw new ArithmeticException("Both operands of gcd equal zero.");

            if (IsZero())
                return new GF2Polynomial(G);
            if (G.IsZero())
                return new GF2Polynomial(this);
            
            GF2Polynomial a = new GF2Polynomial(this);
            GF2Polynomial b = new GF2Polynomial(G);
            GF2Polynomial c;

            while (!b.IsZero())
            {
                c = a.Remainder(b);
                a = b;
                b = c;
            }

            return a;
        }

        /// <summary>
        /// Toggles the LSB of this GF2Polynomial, increasing the value by 'one' and returns the result in a new GF2Polynomial
        /// </summary>
        /// 
        /// <returns>Returns <c>this + 1</c></returns>
        public GF2Polynomial Increase()
        {
            GF2Polynomial result = new GF2Polynomial(this);
            result.IncreaseThis();

            return result;
        }

        /// <summary>
        /// Toggles the LSB of this GF2Polynomial, increasing its value by 'one'
        /// </summary>
        public void IncreaseThis()
        {
            XorBit(0);
        }

        /// <summary>
        /// Checks if <c>this</c> is irreducible, according to IEEE P1363, A.5.5, p103.
        /// <para>Note: The algorithm from IEEE P1363, A5.5 can be used to check a polynomial with coefficients in GF(2^r) for irreducibility.
        /// As this class only represents polynomials with coefficients in GF(2), the algorithm is adapted to the case r=1.</para>
        /// </summary>
        /// 
        /// <returns>Returns true if <c>this</c> is irreducible</returns>
        public bool IsIrreducible()
        {
            if (IsZero())
                return false;

            GF2Polynomial f = new GF2Polynomial(this);
            int d, i;
            GF2Polynomial u, g;
            GF2Polynomial dummy;
            f.ReduceN();
            d = f.m_length - 1;
            u = new GF2Polynomial(f.m_length, "X");

            for (i = 1; i <= (d >> 1); i++)
            {
                u.SquareThisPreCalc();
                u = u.Remainder(f);
                dummy = u.Add(new GF2Polynomial(32, "X"));

                if (!dummy.IsZero())
                {
                    g = f.Gcd(dummy);
                    if (!g.IsOne())
                        return false;
                }
                else
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Tests if all bits are reset to 0 and LSB is set to 1
        /// </summary>
        /// 
        /// <returns>Returns true if this GF2Polynomial equals 'one' (<c>this</c> == 1)</returns>
        public bool IsOne()
        {
            for (int i = 1; i < m_blocks; i++)
            {
                if (m_value[i] != 0)
                    return false;
            }

            if (m_value[0] != 0x01)
                return false;
            
            return true;
        }

        /// <summary>
        /// Tests if all bits equal zero
        /// </summary>
        /// 
        /// <returns>Returns true if this GF2Polynomial equals 'zero' (<c>this</c> == 0)</returns>
        public bool IsZero()
        {
            if (m_length == 0)
                return true;

            for (int i = 0; i < m_blocks; i++)
            {
                if (m_value[i] != 0)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Multiplies this GF2Polynomial with <c>B</c> and returns the result in a new GF2Polynomial. 
        /// This method does not reduce the result in GF(2^N).
        /// This method uses Karatzuba multiplication.
        /// </summary>
        /// 
        /// <param name="B"> GF2Polynomial</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (<c>this</c> * <c>B</c>)</returns>
        public GF2Polynomial Multiply(GF2Polynomial B)
        {
            int n = Math.Max(m_length, B.m_length);
            ExpandN(n);
            B.ExpandN(n);

            return KaraMult(B);
        }

        /// <summary>
        /// Multiplies this GF2Polynomial with <c>B</c> and returns the result in a new GF2Polynomial. This method does not reduce the result in GF(2^N).
        /// This method uses classic multiplication (schoolbook).
        /// </summary>
        /// 
        /// <param name="B">A GF2Polynomial</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (<c>this</c> * <c>B</c>)</returns>
        public GF2Polynomial MultiplyClassic(GF2Polynomial B)
        {
            GF2Polynomial result = new GF2Polynomial(Math.Max(m_length, B.m_length) << 1);
            GF2Polynomial[] m = new GF2Polynomial[32];
            int i, j;
            m[0] = new GF2Polynomial(this);

            for (i = 1; i <= 31; i++)
                m[i] = m[i - 1].ShiftLeft();
            
            for (i = 0; i < B.m_blocks; i++)
            {
                for (j = 0; j <= 31; j++)
                {
                    if ((B.m_value[i] & m_bitMask[j]) != 0)
                        result.XorThisBy(m[j]);
                }

                for (j = 0; j <= 31; j++)
                    m[j].ShiftBlocksLeft();
            }

            return result;
        }

        /// <summary>
        /// Returns the absolute quotient of <c>this</c> divided by <c>G</c> in a new GF2Polynomial
        /// </summary>
        /// 
        /// <param name="G">A GF2Polynomial != 0</param>
        /// 
        /// <returns>Returns a new GF2Polynomial |_ <c>this</c> / <c>G</c></returns>
        public GF2Polynomial Quotient(GF2Polynomial G)
        {
            // a div b = q / r
            GF2Polynomial q = new GF2Polynomial(m_length);
            GF2Polynomial a = new GF2Polynomial(this);
            GF2Polynomial b = new GF2Polynomial(G);
            GF2Polynomial j;
            int i;

            if (b.IsZero())
                throw new Exception();
            
            a.ReduceN();
            b.ReduceN();
            if (a.m_length < b.m_length)
                return new GF2Polynomial(0);
            
            i = a.m_length - b.m_length;
            q.ExpandN(i + 1);

            while (i >= 0)
            {
                j = b.ShiftLeft(i);
                a.SubtractFromThis(j);
                a.ReduceN();
                q.XorBit(i);
                i = a.m_length - b.m_length;
            }

            return q;
        }

        /// <summary>
        /// Fills all len bits of this GF2Polynomial with random values
        /// </summary>
        public void Randomize()
        {
            for (int i = 0; i < m_blocks; i++)
                m_value[i] = m_rand.Next();
            
            ZeroUnusedBits();
        }

        /// <summary>
        /// Fills all len bits of this GF2Polynomial with random values using the specified source of randomness
        /// </summary>
        /// 
        /// <param name="Rand">The source of randomness</param>
        public void Randomize(Random Rand)
        {
            for (int i = 0; i < m_blocks; i++)
                m_value[i] = Rand.Next();
            
            ZeroUnusedBits();
        }

        /// <summary>
        /// Reduces len by finding the most significant bit set to one and reducing len and blocks
        /// </summary>
        public void ReduceN()
        {
            int i, j, h;
            i = m_blocks - 1;
            while ((m_value[i] == 0) && (i > 0))
            {
                i--;
            }

            h = m_value[i];
            j = 0;
            while (h != 0)
            {
                h = IntUtils.URShift(h, 1);
                j++;
            }
            m_length = (i << 5) + j;
            m_blocks = i + 1;
        }

        /// <summary>
        /// Reduces this GF2Polynomial using the pentanomial x^<c>M</c> + x^<c>Pc[2]</c> + x^<c>Pc[1]</c> + x^<c>Pc[0]</c> + 1
        /// </summary>
        /// 
        /// <param name="M">The degree of the used field</param>
        /// <param name="Pc">The degrees of the middle x's in the pentanomial</param>
        public void ReducePentanomial(int M, int[] Pc)
        {
            int i;
            int p0, p1, p2, p3;
            int q0, q1, q2, q3;
            long t;
            p0 = IntUtils.URShift(M, 5);
            q0 = 32 - (M & 0x1f);
            p1 = IntUtils.URShift((M - Pc[0]), 5);
            q1 = 32 - ((M - Pc[0]) & 0x1f);
            p2 = IntUtils.URShift((M - Pc[1]), 5);
            q2 = 32 - ((M - Pc[1]) & 0x1f);
            p3 = IntUtils.URShift((M - Pc[2]), 5);
            q3 = 32 - ((M - Pc[2]) & 0x1f);

            int max = IntUtils.URShift(((M << 1) - 2), 5);
            int min = p0;

            for (i = max; i > min; i--)
            {
                t = m_value[i] & 0x00000000ffffffffL;
                m_value[i - p0 - 1] ^= (int)(t << q0);
                m_value[i - p0] ^= IntUtils.URShift((int)t, (32 - q0));
                m_value[i - p1 - 1] ^= (int)(t << q1);
                m_value[i - p1] ^= IntUtils.URShift((int)t, (32 - q1));
                m_value[i - p2 - 1] ^= (int)(t << q2);
                m_value[i - p2] ^= IntUtils.URShift((int)t, (32 - q2));
                m_value[i - p3 - 1] ^= (int)(t << q3);
                m_value[i - p3] ^= IntUtils.URShift((int)t, (32 - q3));
                m_value[i] = 0;
            }

            t = m_value[min] & 0x00000000ffffffffL & (0xffffffffL << (M & 0x1f));
            m_value[0] ^= IntUtils.URShift((int)t, (32 - q0));

            if (min - p1 - 1 >= 0)
                m_value[min - p1 - 1] ^= (int)(t << q1);

            m_value[min - p1] ^= IntUtils.URShift((int)t, (32 - q1));
            if (min - p2 - 1 >= 0)
                m_value[min - p2 - 1] ^= (int)(t << q2);
            
            m_value[min - p2] ^= IntUtils.URShift((int)t, (32 - q2));
            if (min - p3 - 1 >= 0)
                m_value[min - p3 - 1] ^= (int)(t << q3);
            
            m_value[min - p3] ^= IntUtils.URShift((int)t, (32 - q3));
            m_value[min] &= m_reverseRightMask[M & 0x1f];
            m_blocks = (IntUtils.URShift((int)(M - 1), 5)) + 1;
            m_length = M;
        }

        /// <summary>
        /// Reduces this GF2Polynomial using the trinomial x^<c>M</c> + x^<c>Tc</c> + 1
        /// </summary>
        /// 
        /// <param name="M">The degree of the used field</param>
        /// <param name="Tc">The degree of the middle x in the trinomial</param>
        public void ReduceTrinomial(int M, int Tc)
        {
            int i;
            int p0, p1;
            int q0, q1;
            long t;
            p0 = IntUtils.URShift(M, 5); // block which contains 2^m
            q0 = 32 - (M & 0x1f); // (32-index) of 2^m within block p0
            p1 = IntUtils.URShift((M - Tc), 5); // block which contains 2^tc
            q1 = 32 - ((M - Tc) & 0x1f); // (32-index) of 2^tc within block q1
            int max = IntUtils.URShift(((M << 1) - 2), 5); // block which contains 2^(2m-2)
            int min = p0; // block which contains 2^m

            for (i = max; i > min; i--)
            { // for i = maxBlock to minBlock
                // reduce coefficients contained in t
                // t = block[i]
                t = m_value[i] & 0x00000000ffffffffL;
                // block[i-p0-1] ^= t << q0
                m_value[i - p0 - 1] ^= (int)(t << q0);
                // block[i-p0] ^= t >>> (32-q0)
                m_value[i - p0] ^= IntUtils.URShift((int)t, (32 - q0));
                // block[i-p1-1] ^= << q1
                m_value[i - p1 - 1] ^= (int)(t << q1);
                // block[i-p1] ^= t >>> (32-q1)
                m_value[i - p1] ^= IntUtils.URShift((int)t, (32 - q1));
                m_value[i] = 0x00;
            }

            // reduce last coefficients in block containing 2^m
            t = m_value[min] & 0x00000000ffffffffL & (0xffffffffL << (M & 0x1f)); // t
            // contains the last coefficients > m
            m_value[0] ^= IntUtils.URShift((int)t, (32 - q0));
            if (min - p1 - 1 >= 0)
                m_value[min - p1 - 1] ^= (int)(t << q1);
            
            m_value[min - p1] ^= IntUtils.URShift((int)t, (32 - q1));
            m_value[min] &= m_reverseRightMask[M & 0x1f];
            m_blocks = (IntUtils.URShift((M - 1), 5)) + 1;
            m_length = M;
        }

        /// <summary>
        /// Returns the remainder of <c>this</c> divided by <c>G</c> in a new GF2Polynomial
        /// </summary>
        /// 
        /// <param name="G">A GF2Polynomial != 0</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (<c>this</c> % <c>G</c>)</returns>
        public GF2Polynomial Remainder(GF2Polynomial G)
        {
            // a div b = q / r
            GF2Polynomial a = new GF2Polynomial(this);
            GF2Polynomial b = new GF2Polynomial(G);
            GF2Polynomial j;
            int i;

            if (b.IsZero())
                throw new Exception();
            
            a.ReduceN();
            b.ReduceN();

            if (a.m_length < b.m_length)
                return a;
            
            i = a.m_length - b.m_length;
            while (i >= 0)
            {
                j = b.ShiftLeft(i);
                a.SubtractFromThis(j);
                a.ReduceN();
                i = a.m_length - b.m_length;
            }

            return a;
        }

        /// <summary>
        /// Resets the bit at position <c>Index</c>
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        public void ResetBit(int Index)
        {
            if (Index < 0 || Index > (m_length - 1))
                throw new Exception();
            if (Index > (m_length - 1))
                return;
            
            m_value[IntUtils.URShift(Index, 5)] &= ~m_bitMask[Index & 0x1f];
        }

        /// <summary>
        /// Sets the bit at position <c>Index</c>
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        public void SetBit(int Index)
        {
            if (Index < 0 || Index > (m_length - 1))
                throw new Exception();
            if (Index > (m_length - 1))
                return;

            m_value[IntUtils.URShift(Index, 5)] |= m_bitMask[Index & 0x1f];

            return;
        }

        /// <summary>
        /// Returns this GF2Polynomial shift-left by 1 in a new GF2Polynomial
        /// </summary>
        /// 
        /// <returns>Returns a new GF2Polynomial (this &lt;&lt; 1)</returns>
        public GF2Polynomial ShiftLeft()
        {
            GF2Polynomial result = new GF2Polynomial(m_length + 1, m_value);

            for (int i = result.m_blocks - 1; i >= 1; i--)
            {
                result.m_value[i] <<= 1;
                result.m_value[i] |= IntUtils.URShift(result.m_value[i - 1], 31);
            }
            result.m_value[0] <<= 1;

            return result;
        }

        /// <summary>
        /// Returns this GF2Polynomial shift-left by <c>K</c> in a new GF2Polynomial
        /// </summary>
        /// 
        /// <param name="K">The shift value</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (this &lt;&lt; <c>K</c>)</returns>
        public GF2Polynomial ShiftLeft(int K)
        {
            // Variant 2, requiring a modified shiftBlocksLeft(k)
            // In case of modification, consider a rename to DoShiftBlocksLeft()
            // with an explicit note that this method assumes that the polynomial
            // has already been resized. Or consider doing things inline.
            // Construct the resulting polynomial of appropriate length:
            GF2Polynomial result = new GF2Polynomial(m_length + K, m_value);
            // Shift left as many multiples of the block size as possible:
            if (K >= 32)
                result.DoShiftBlocksLeft(IntUtils.URShift(K, 5));
            
            // Shift left by the remaining (<32) amount:
            int remaining = K & 0x1f;
            if (remaining != 0)
            {
                for (int i = result.m_blocks - 1; i >= 1; i--)
                {
                    result.m_value[i] <<= remaining;
                    result.m_value[i] |= IntUtils.URShift(result.m_value[i - 1], (32 - remaining));
                }
                result.m_value[0] <<= remaining;
            }

            return result;
        }

        /// <summary>
        /// Shifts left b and adds the result to Its a fast version of <c>this = Add(b.Shl(K));</c>
        /// </summary>
        /// 
        /// <param name="B">GF2Polynomial to shift and add to this</param>
        /// <param name="K">The amount to shift</param>
        public void ShiftLeftAddThis(GF2Polynomial B, int K)
        {
            if (K == 0)
            {
                AddToThis(B);
                return;
            }

            int i;
            ExpandN(B.m_length + K);
            int d = IntUtils.URShift(K, 5);

            for (i = B.m_blocks - 1; i >= 0; i--)
            {
                if ((i + d + 1 < m_blocks) && ((K & 0x1f) != 0))
                    m_value[i + d + 1] ^= IntUtils.URShift(B.m_value[i], (32 - (K & 0x1f)));
                
                m_value[i + d] ^= B.m_value[i] << (K & 0x1f);
            }
        }

        /// <summary>
        /// Shifts-left this by one and enlarges the size of value if necesary.
        /// </summary>
        public void ShiftLeftThis()
        {
            // This is untested
            int i;
            // check if blocks increases
            if ((m_length & 0x1f) == 0)
            {
                m_length += 1;
                m_blocks += 1;
                if (m_blocks > m_value.Length)
                { // enlarge value
                    int[] bs = new int[m_blocks];
                    Array.Copy(m_value, 0, bs, 0, m_value.Length);
                    m_value = null;
                    m_value = bs;
                }
                for (i = m_blocks - 1; i >= 1; i--)
                {
                    m_value[i] |= IntUtils.URShift(m_value[i - 1], 31);
                    m_value[i - 1] <<= 1;
                }
            }
            else
            {
                m_length += 1;
                for (i = m_blocks - 1; i >= 1; i--)
                {
                    m_value[i] <<= 1;
                    m_value[i] |= IntUtils.URShift(m_value[i - 1], 31);
                }
                m_value[0] <<= 1;
            }
        }

        /// <summary>
        /// Returns this GF2Polynomial shift-right by 1 in a new GF2Polynomial
        /// </summary>
        /// 
        /// <returns>Returns a new GF2Polynomial (this &lt;&lt; 1)</returns>
        public GF2Polynomial ShiftRight()
        {
            GF2Polynomial result = new GF2Polynomial(m_length - 1);
            int i;
            Array.Copy(m_value, 0, result.m_value, 0, result.m_blocks);

            for (i = 0; i <= result.m_blocks - 2; i++)
            {
                result.m_value[i] = IntUtils.URShift(result.m_value[i], 1);
                result.m_value[i] |= result.m_value[i + 1] << 31;
            }

            result.m_value[result.m_blocks - 1] = IntUtils.URShift(result.m_value[result.m_blocks - 1], 1);
            if (result.m_blocks < m_blocks)
                result.m_value[result.m_blocks - 1] |= m_value[result.m_blocks] << 31;

            return result;
        }

        /// <summary>
        /// Shifts-right this GF2Polynomial by 1
        /// </summary>
        public void ShiftRightThis()
        {
            int i;
            m_length -= 1;
            m_blocks = (IntUtils.URShift((m_length - 1), 5)) + 1;

            for (i = 0; i <= m_blocks - 2; i++)
            {
                m_value[i] = IntUtils.URShift(m_value[i], 1);
                m_value[i] |= m_value[i + 1] << 31;
            }

            m_value[m_blocks - 1] = IntUtils.URShift(m_value[m_blocks - 1], 1);
            if ((m_length & 0x1f) == 0)
                m_value[m_blocks - 1] |= m_value[m_blocks] << 31;
        }

        /// <summary>
        /// Squares this GF2Polynomial and expands it accordingly.
        /// <para>This method does not reduce the result in GF(2^N).
        /// There exists a faster method for squaring in GF(2^N).</para>
        /// </summary>
        public void SquareThisBitwise()
        {
            int i, h, j, k;
            if (IsZero())
                return;
            
            int[] result = new int[m_blocks << 1];
            for (i = m_blocks - 1; i >= 0; i--)
            {
                h = m_value[i];
                j = 0x00000001;

                for (k = 0; k < 16; k++)
                {
                    if ((h & 0x01) != 0)
                        result[i << 1] |= j;
                    if ((h & 0x00010000) != 0)
                        result[(i << 1) + 1] |= j;
                    
                    j <<= 2;
                    h = IntUtils.URShift(h, 1);
                }
            }
            m_value = null;
            m_value = result;
            m_blocks = result.Length;
            m_length = (m_length << 1) - 1;
        }

        /// <summary>
        /// Squares this GF2Polynomial by using precomputed values of squaringTable.
        /// <para>This method does not reduce the result in GF(2^N).</para>
        /// </summary>
        public void SquareThisPreCalc()
        {
            int i;
            if (IsZero())
                return;
            
            if (m_value.Length >= (m_blocks << 1))
            {
                for (i = m_blocks - 1; i >= 0; i--)
                {

                    m_value[(i << 1) + 1] = (int)GF2Polynomial.m_squaringTable[IntUtils.URShift((m_value[i] & 0x00ff0000), 16)] | (GF2Polynomial.m_squaringTable[IntUtils.URShift((m_value[i] & 0xff000000), 24)] << 16);
                    m_value[i << 1] = (int)GF2Polynomial.m_squaringTable[m_value[i] & 0x000000ff] | (GF2Polynomial.m_squaringTable[IntUtils.URShift((m_value[i] & 0x0000ff00), 8)] << 16);
                }
                m_blocks <<= 1;
                m_length = (m_length << 1) - 1;
            }
            else
            {
                int[] result = new int[m_blocks << 1];
                for (i = 0; i < m_blocks; i++)
                {
                    result[i << 1] = (int)GF2Polynomial.m_squaringTable[m_value[i] & 0x000000ff] | (GF2Polynomial.m_squaringTable[IntUtils.URShift((m_value[i] & 0x0000ff00), 8)] << 16);
                    result[(i << 1) + 1] = (int)GF2Polynomial.m_squaringTable[IntUtils.URShift((m_value[i] & 0x00ff0000), 16)] | (GF2Polynomial.m_squaringTable[IntUtils.URShift((m_value[i] & 0xff000000), 24)] << 16);
                }
                m_value = null;
                m_value = result;
                m_blocks <<= 1;
                m_length = (m_length << 1) - 1;
            }
        }

        /// <summary>
        /// Subtracts two GF2Polynomials, <c>this</c> and <c>B</c>, and returns the result in a new GF2Polynomial.
        /// <c>this</c> and <c>B</c> can be of different size.
        /// </summary>
        /// 
        /// <param name="B">A GF2Polynomial</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (<c>this</c> - <c>b</c>)</returns>
        public GF2Polynomial Subtract(GF2Polynomial B)
        {
            return Xor(B);
        }

        /// <summary>
        /// Subtracts <c>B</c> from this GF2Polynomial and assigns the result to this GF2Polynomial.
        /// <c>B</c> can be of different size.
        /// </summary>
        /// 
        /// <param name="B">A GF2Polynomial</param>
        public void SubtractFromThis(GF2Polynomial B)
        {
            ExpandN(B.m_length);
            XorThisBy(B);
        }

        /// <summary>
        /// Tests the bit at position <c>Index</c>
        /// </summary>
        /// 
        /// <param name="Index">he position of the bit to be tested</param>
        /// 
        /// <returns>Returns true if the bit at position <c>i</c> is set (a(<c>Index</c>) == 1). False if (<c>Index</c> &lt; 0) || (<c>Index</c> &gt; (len - 1))</returns>
        public bool TestBit(int Index)
        {
            if (Index < 0 || Index > (m_length - 1))
                return false;
            
            return (m_value[IntUtils.URShift(Index, 5)] & m_bitMask[Index & 0x1f]) != 0;
        }

        /// <summary>
        /// Does a vector-multiplication modulo 2 and returns the result as boolean
        /// </summary>
        /// 
        /// <param name="B">The GF2Polynomial</param>
        /// 
        /// <returns>Returns this x <c>B</c> as boolean (1-&gt;true, 0-&gt;false)</returns>
        public bool VectorMult(GF2Polynomial B)
        {
            int i;
            int h;
            bool result = false;

            if (m_length != B.m_length)
                throw new Exception("Length mismatch, invalid vector!");
            
            for (i = 0; i < m_blocks; i++)
            {
                h = m_value[i] & B.m_value[i];
                result ^= m_parity[h & 0x000000ff];
                result ^= m_parity[(IntUtils.URShift(h, 8)) & 0x000000ff];
                result ^= m_parity[(IntUtils.URShift(h, 16)) & 0x000000ff];
                result ^= m_parity[(IntUtils.URShift(h, 24)) & 0x000000ff];
            }

            return result;
        }

        /// <summary>
        /// Returns the bitwise exclusive-or of <c>this</c> and <c>B</c> in a new GF2Polynomial;
        /// <c>this</c> and <c>B</c> can be of different size.
        /// </summary>
        /// 
        /// <param name="B">The GF2Polynomial</param>
        /// 
        /// <returns>Returns a new GF2Polynomial (<c>this</c> ^ <c>B</c>)</returns>
        public GF2Polynomial Xor(GF2Polynomial B)
        {
            int i;
            GF2Polynomial result;
            int k = Math.Min(m_blocks, B.m_blocks);

            if (m_length >= B.m_length)
            {
                result = new GF2Polynomial(this);
                for (i = 0; i < k; i++)
                    result.m_value[i] ^= B.m_value[i];
            }
            else
            {
                result = new GF2Polynomial(B);
                for (i = 0; i < k; i++)
                    result.m_value[i] ^= m_value[i];
            }
            // If we xor'ed some bits too many by proceeding blockwise, restore them to zero:
            result.ZeroUnusedBits();

            return result;
        }

        /// <summary>
        /// Xors the bit at position <c>Index</c>
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        public void XorBit(int Index)
        {
            if (Index < 0 || Index > (m_length - 1))
                throw new Exception();
            if (Index > (m_length - 1))
                return;
            
            m_value[IntUtils.URShift(Index, 5)] ^= m_bitMask[Index & 0x1f];
        }

        /// <summary>
        /// Computes the bitwise exclusive-or of this GF2Polynomial and <c>B</c> and stores the result in this GF2Polynomial;
        /// <c>B</c> can be of different size.
        /// </summary>
        /// 
        /// <param name="B">The GF2Polynomial</param>
        public void XorThisBy(GF2Polynomial B)
        {
            for (int i = 0; i < Math.Min(m_blocks, B.m_blocks); i++)
                m_value[i] ^= B.m_value[i];

            // If we xor'ed some bits too many by proceeding blockwise, restore them to zero:
            ZeroUnusedBits();
        }

        /// <summary>
        /// If Length is not a multiple of the block size (32), some extra bits of the last block might have been modified during a blockwise operation.
        /// This method compensates for that by restoring these "extra" bits to zero.
        /// </summary>
        private void ZeroUnusedBits()
        {
            if ((m_length & 0x1f) != 0)
                m_value[m_blocks - 1] &= m_reverseRightMask[m_length & 0x1f];
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compare this element with another object
        /// </summary>
        /// 
        /// <param name="Obj">The object for comprison</param>
        /// 
        /// <returns>Returns <c>true</c> if the two objects are equal, <c>false</c> otherwise</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is GF2Polynomial))
                return false;

            GF2Polynomial otherPol = (GF2Polynomial)Obj;

            if (m_length != otherPol.m_length)
                return false;
            
            for (int i = 0; i < m_blocks; i++)
            {
                if (m_value[i] != otherPol.m_value[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the hash code of this element
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return m_length * 31 + m_value.GetHashCode();
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Shifts left this GF2Polynomial's value blockwise <c>B</c> blocks resulting in a shift-left by b*32.
        /// This method assumes that Length and blocks have already been updated to reflect the final state.
        /// </summary>
        /// 
        /// <param name="B">The shift amount (in blocks)</param>
        private void DoShiftBlocksLeft(int B)
        {
            if (m_blocks <= m_value.Length)
            {
                int i;
                for (i = m_blocks - 1; i >= B; i--)
                    m_value[i] = m_value[i - B];
                for (i = 0; i < B; i++)
                    m_value[i] = 0x00;
            }
            else
            {
                int[] result = new int[m_blocks];
                Array.Copy(m_value, 0, result, B, m_blocks - B);
                m_value = null;
                m_value = result;
            }
        }

        /// <summary>
        /// Does the recursion for Karatzuba multiplication
        /// </summary>
        /// 
        /// <param name="B">A GF2Polynomial</param>
        /// 
        /// <returns><c>this * B</c></returns>
        private GF2Polynomial KaraMult(GF2Polynomial B)
        {
            GF2Polynomial result = new GF2Polynomial(m_length << 1);
            if (m_length <= 32)
            {
                result.m_value = Mult32(m_value[0], B.m_value[0]);
                return result;
            }
            if (m_length <= 64)
            {
                result.m_value = Mult64(m_value, B.m_value);
                return result;
            }
            if (m_length <= 128)
            {
                result.m_value = Mult128(m_value, B.m_value);
                return result;
            }
            if (m_length <= 256)
            {
                result.m_value = Mult256(m_value, B.m_value);
                return result;
            }
            if (m_length <= 512)
            {
                result.m_value = Mult512(m_value, B.m_value);
                return result;
            }

            int n = BigMath.FloorLog(m_length - 1);
            n = m_bitMask[n];

            GF2Polynomial a0 = Lower(((n - 1) >> 5) + 1);
            GF2Polynomial a1 = Upper(((n - 1) >> 5) + 1);
            GF2Polynomial b0 = B.Lower(((n - 1) >> 5) + 1);
            GF2Polynomial b1 = B.Upper(((n - 1) >> 5) + 1);
            GF2Polynomial c = a1.KaraMult(b1); // c = a1*b1
            GF2Polynomial e = a0.KaraMult(b0); // e = a0*b0
            a0.AddToThis(a1); // a0 = a0 + a1
            b0.AddToThis(b1); // b0 = b0 + b1

            GF2Polynomial d = a0.KaraMult(b0); // d = (a0+a1)*(b0+b1)
            result.ShiftLeftAddThis(c, n << 1);
            result.ShiftLeftAddThis(c, n);
            result.ShiftLeftAddThis(d, n);
            result.ShiftLeftAddThis(e, n);
            result.AddToThis(e);

            return result;
        }

        /// <summary>
        /// Returns a new GF2Polynomial containing the lower <c>K</c> bytes of this GF2Polynomial
        /// </summary>
        private GF2Polynomial Lower(int K)
        {
            GF2Polynomial result = new GF2Polynomial(K << 5);
            Array.Copy(m_value, 0, result.m_value, 0, Math.Min(K, m_blocks));

            return result;
        }

        /// <summary>
        /// 4-Byte Version of Karatzuba multiplication. Here the actual work is done
        /// </summary>
        private static int[] Mult32(int a, int b)
        {
            int[] result = new int[2];
            if (a == 0 || b == 0)
                return result;
            
            long b2 = b;
            b2 &= 0x00000000ffffffffL;
            int i;
            long h = 0;
            for (i = 1; i <= 32; i++)
            {
                if ((a & m_bitMask[i - 1]) != 0)
                    h ^= b2;
                
                b2 <<= 1;
            }
            result[1] = (int)(IntUtils.URShift(h, 32));
            result[0] = (int)(h & 0x00000000ffffffffL);

            return result;
        }

        /// <summary>
        /// 2-Integer Version of Karatzuba multiplication
        /// </summary>
        private static int[] Mult64(int[] A, int[] B)
        {
            int[] result = new int[4];
            int a0 = A[0];
            int a1 = 0;
            if (A.Length > 1)
                a1 = A[1];
            
            int b0 = B[0];
            int b1 = 0;
            if (B.Length > 1)
                b1 = B[1];
            
            if (a1 != 0 || b1 != 0)
            {
                int[] c = Mult32(a1, b1);
                result[3] ^= c[1];
                result[2] ^= c[0] ^ c[1];
                result[1] ^= c[0];
            }
            int[] d = Mult32(a0 ^ a1, b0 ^ b1);
            result[2] ^= d[1];
            result[1] ^= d[0];
            int[] e = Mult32(a0, b0);
            result[2] ^= e[1];
            result[1] ^= e[0] ^ e[1];
            result[0] ^= e[0];

            return result;
        }

        /// <summary>
        /// 4-Integer Version of Karatzuba multiplication
        /// </summary>
        private static int[] Mult128(int[] A, int[] B)
        {
            int[] result = new int[8];
            int[] a0 = new int[2];
            Array.Copy(A, 0, a0, 0, Math.Min(2, A.Length));
            int[] a1 = new int[2];
            if (A.Length > 2)
                Array.Copy(A, 2, a1, 0, Math.Min(2, A.Length - 2));
            
            int[] b0 = new int[2];
            Array.Copy(B, 0, b0, 0, Math.Min(2, B.Length));
            int[] b1 = new int[2];
            if (B.Length > 2)
                Array.Copy(B, 2, b1, 0, Math.Min(2, B.Length - 2));
            
            if (a1[1] == 0 && b1[1] == 0)
            {
                if (a1[0] != 0 || b1[0] != 0)
                {
                    int[] c = Mult32(a1[0], b1[0]);
                    result[5] ^= c[1];
                    result[4] ^= c[0];
                    result[3] ^= c[1];
                    result[2] ^= c[0];
                }
            }
            else
            {
                int[] c = Mult64(a1, b1);
                result[7] ^= c[3];
                result[6] ^= c[2];
                result[5] ^= c[1] ^ c[3];
                result[4] ^= c[0] ^ c[2];
                result[3] ^= c[1];
                result[2] ^= c[0];
            }
            a1[0] ^= a0[0];
            a1[1] ^= a0[1];
            b1[0] ^= b0[0];
            b1[1] ^= b0[1];
            if (a1[1] == 0 && b1[1] == 0)
            {
                int[] d = Mult32(a1[0], b1[0]);
                result[3] ^= d[1];
                result[2] ^= d[0];
            }
            else
            {
                int[] d = Mult64(a1, b1);
                result[5] ^= d[3];
                result[4] ^= d[2];
                result[3] ^= d[1];
                result[2] ^= d[0];
            }
            if (a0[1] == 0 && b0[1] == 0)
            {
                int[] e = Mult32(a0[0], b0[0]);
                result[3] ^= e[1];
                result[2] ^= e[0];
                result[1] ^= e[1];
                result[0] ^= e[0];
            }
            else
            {
                int[] e = Mult64(a0, b0);
                result[5] ^= e[3];
                result[4] ^= e[2];
                result[3] ^= e[1] ^ e[3];
                result[2] ^= e[0] ^ e[2];
                result[1] ^= e[1];
                result[0] ^= e[0];
            }

            return result;
        }

        /// <summary>
        /// 8-Integer Version of Karatzuba multiplication
        /// </summary>
        private static int[] Mult256(int[] A, int[] B)
        {
            int[] result = new int[16];
            int[] a0 = new int[4];
            Array.Copy(A, 0, a0, 0, Math.Min(4, A.Length));
            int[] a1 = new int[4];
            if (A.Length > 4)
                Array.Copy(A, 4, a1, 0, Math.Min(4, A.Length - 4));
            
            int[] b0 = new int[4];
            Array.Copy(B, 0, b0, 0, Math.Min(4, B.Length));
            int[] b1 = new int[4];
            if (B.Length > 4)
                Array.Copy(B, 4, b1, 0, Math.Min(4, B.Length - 4));
            
            if (a1[3] == 0 && a1[2] == 0 && b1[3] == 0 && b1[2] == 0)
            {
                if (a1[1] == 0 && b1[1] == 0)
                {
                    if (a1[0] != 0 || b1[0] != 0)
                    { // [3]=[2]=[1]=0, [0]!=0
                        int[] c = Mult32(a1[0], b1[0]);
                        result[9] ^= c[1];
                        result[8] ^= c[0];
                        result[5] ^= c[1];
                        result[4] ^= c[0];
                    }
                }
                else
                { // [3]=[2]=0 [1]!=0, [0]!=0
                    int[] c = Mult64(a1, b1);
                    result[11] ^= c[3];
                    result[10] ^= c[2];
                    result[9] ^= c[1];
                    result[8] ^= c[0];
                    result[7] ^= c[3];
                    result[6] ^= c[2];
                    result[5] ^= c[1];
                    result[4] ^= c[0];
                }
            }
            else
            { // [3]!=0 [2]!=0 [1]!=0, [0]!=0
                int[] c = Mult128(a1, b1);
                result[15] ^= c[7];
                result[14] ^= c[6];
                result[13] ^= c[5];
                result[12] ^= c[4];
                result[11] ^= c[3] ^ c[7];
                result[10] ^= c[2] ^ c[6];
                result[9] ^= c[1] ^ c[5];
                result[8] ^= c[0] ^ c[4];
                result[7] ^= c[3];
                result[6] ^= c[2];
                result[5] ^= c[1];
                result[4] ^= c[0];
            }
            a1[0] ^= a0[0];
            a1[1] ^= a0[1];
            a1[2] ^= a0[2];
            a1[3] ^= a0[3];
            b1[0] ^= b0[0];
            b1[1] ^= b0[1];
            b1[2] ^= b0[2];
            b1[3] ^= b0[3];
            int[] d = Mult128(a1, b1);
            result[11] ^= d[7];
            result[10] ^= d[6];
            result[9] ^= d[5];
            result[8] ^= d[4];
            result[7] ^= d[3];
            result[6] ^= d[2];
            result[5] ^= d[1];
            result[4] ^= d[0];
            int[] e = Mult128(a0, b0);
            result[11] ^= e[7];
            result[10] ^= e[6];
            result[9] ^= e[5];
            result[8] ^= e[4];
            result[7] ^= e[3] ^ e[7];
            result[6] ^= e[2] ^ e[6];
            result[5] ^= e[1] ^ e[5];
            result[4] ^= e[0] ^ e[4];
            result[3] ^= e[3];
            result[2] ^= e[2];
            result[1] ^= e[1];
            result[0] ^= e[0];

            return result;
        }

        /// <summary>
        /// 16-Integer Version of Karatzuba multiplication
        /// </summary>
        private static int[] Mult512(int[] A, int[] B)
        {
            int[] result = new int[32];
            int[] a0 = new int[8];
            Array.Copy(A, 0, a0, 0, Math.Min(8, A.Length));
            int[] a1 = new int[8];
            if (A.Length > 8)
                Array.Copy(A, 8, a1, 0, Math.Min(8, A.Length - 8));
            
            int[] b0 = new int[8];
            Array.Copy(B, 0, b0, 0, Math.Min(8, B.Length));
            int[] b1 = new int[8];
            if (B.Length > 8)
                Array.Copy(B, 8, b1, 0, Math.Min(8, B.Length - 8));
            
            int[] c = Mult256(a1, b1);
            result[31] ^= c[15];
            result[30] ^= c[14];
            result[29] ^= c[13];
            result[28] ^= c[12];
            result[27] ^= c[11];
            result[26] ^= c[10];
            result[25] ^= c[9];
            result[24] ^= c[8];
            result[23] ^= c[7] ^ c[15];
            result[22] ^= c[6] ^ c[14];
            result[21] ^= c[5] ^ c[13];
            result[20] ^= c[4] ^ c[12];
            result[19] ^= c[3] ^ c[11];
            result[18] ^= c[2] ^ c[10];
            result[17] ^= c[1] ^ c[9];
            result[16] ^= c[0] ^ c[8];
            result[15] ^= c[7];
            result[14] ^= c[6];
            result[13] ^= c[5];
            result[12] ^= c[4];
            result[11] ^= c[3];
            result[10] ^= c[2];
            result[9] ^= c[1];
            result[8] ^= c[0];
            a1[0] ^= a0[0];
            a1[1] ^= a0[1];
            a1[2] ^= a0[2];
            a1[3] ^= a0[3];
            a1[4] ^= a0[4];
            a1[5] ^= a0[5];
            a1[6] ^= a0[6];
            a1[7] ^= a0[7];
            b1[0] ^= b0[0];
            b1[1] ^= b0[1];
            b1[2] ^= b0[2];
            b1[3] ^= b0[3];
            b1[4] ^= b0[4];
            b1[5] ^= b0[5];
            b1[6] ^= b0[6];
            b1[7] ^= b0[7];
            int[] d = Mult256(a1, b1);
            result[23] ^= d[15];
            result[22] ^= d[14];
            result[21] ^= d[13];
            result[20] ^= d[12];
            result[19] ^= d[11];
            result[18] ^= d[10];
            result[17] ^= d[9];
            result[16] ^= d[8];
            result[15] ^= d[7];
            result[14] ^= d[6];
            result[13] ^= d[5];
            result[12] ^= d[4];
            result[11] ^= d[3];
            result[10] ^= d[2];
            result[9] ^= d[1];
            result[8] ^= d[0];
            int[] e = Mult256(a0, b0);
            result[23] ^= e[15];
            result[22] ^= e[14];
            result[21] ^= e[13];
            result[20] ^= e[12];
            result[19] ^= e[11];
            result[18] ^= e[10];
            result[17] ^= e[9];
            result[16] ^= e[8];
            result[15] ^= e[7] ^ e[15];
            result[14] ^= e[6] ^ e[14];
            result[13] ^= e[5] ^ e[13];
            result[12] ^= e[4] ^ e[12];
            result[11] ^= e[3] ^ e[11];
            result[10] ^= e[2] ^ e[10];
            result[9] ^= e[1] ^ e[9];
            result[8] ^= e[0] ^ e[8];
            result[7] ^= e[7];
            result[6] ^= e[6];
            result[5] ^= e[5];
            result[4] ^= e[4];
            result[3] ^= e[3];
            result[2] ^= e[2];
            result[1] ^= e[1];
            result[0] ^= e[0];

            return result;
        }

        /// <summary>
        /// Shifts-left this GF2Polynomial's value blockwise 1 block resulting in a shift-left by 32
        /// </summary>
        private void ShiftBlocksLeft()
        {
            m_blocks += 1;
            m_length += 32;

            if (m_blocks <= m_value.Length)
            {
                int i;
                for (i = m_blocks - 1; i >= 1; i--)
                    m_value[i] = m_value[i - 1];

                m_value[0] = 0x00;
            }
            else
            {
                int[] result = new int[m_blocks];
                Array.Copy(m_value, 0, result, 1, m_blocks - 1);
                m_value = null;
                m_value = result;
            }
        }

        /// <summary>
        /// Returns a new GF2Polynomial containing the upper <c>K</c> bytes of this GF2Polynomial
        /// </summary>
        private GF2Polynomial Upper(int K)
        {
            int j = Math.Min(K, m_blocks - K);
            GF2Polynomial result = new GF2Polynomial(j << 5);

            if (m_blocks >= K)
                Array.Copy(m_value, K, result.m_value, 0, j);
            
            return result;
        }
        #endregion
    }
}
