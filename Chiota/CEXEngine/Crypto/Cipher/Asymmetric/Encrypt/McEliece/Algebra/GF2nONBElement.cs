#region Directives
using System;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements an element of the finite field <c>GF(2^n)</c>.
    /// <para>It is represented in an optimal normal basis representation and holds the pointer <c>m_Field</c> to its corresponding field.</para>
    /// </summary>
    internal sealed class GF2nONBElement : GF2nElement
    {
        #region Fields
        private static int MAXLONG = 64;
        // holds the lenght of the polynomial with 64 bit sized fields.
        private int m_Length;
        // holds the value of mDeg % MAXLONG.
        private int m_Bit;
        // holds this element in ONB representation.
        private long[] m_Pol;

        private static readonly long[] _mBitmask = new long[]
        {
            0x0000000000000001L, 0x0000000000000002L, 0x0000000000000004L, 0x0000000000000008L, 
            0x0000000000000010L, 0x0000000000000020L, 0x0000000000000040L, 0x0000000000000080L, 
            0x0000000000000100L, 0x0000000000000200L, 0x0000000000000400L, 0x0000000000000800L, 
            0x0000000000001000L, 0x0000000000002000L, 0x0000000000004000L, 0x0000000000008000L,
            0x0000000000010000L, 0x0000000000020000L, 0x0000000000040000L, 0x0000000000080000L, 
            0x0000000000100000L, 0x0000000000200000L, 0x0000000000400000L, 0x0000000000800000L, 
            0x0000000001000000L, 0x0000000002000000L, 0x0000000004000000L, 0x0000000008000000L,
            0x0000000010000000L, 0x0000000020000000L, 0x0000000040000000L, 0x0000000080000000L, 
            0x0000000100000000L, 0x0000000200000000L, 0x0000000400000000L, 0x0000000800000000L, 
            0x0000001000000000L, 0x0000002000000000L, 0x0000004000000000L, 0x0000008000000000L,
            0x0000010000000000L, 0x0000020000000000L, 0x0000040000000000L, 0x0000080000000000L, 
            0x0000100000000000L, 0x0000200000000000L, 0x0000400000000000L, 0x0000800000000000L, 
            0x0001000000000000L,0x0002000000000000L, 0x0004000000000000L, 0x0008000000000000L,
            0x0010000000000000L, 0x0020000000000000L, 0x0040000000000000L, 0x0080000000000000L, 
            0x0100000000000000L, 0x0200000000000000L, 0x0400000000000000L, 0x0800000000000000L, 
            0x1000000000000000L, 0x2000000000000000L, 0x4000000000000000L, unchecked((long)0x8000000000000000L)
        };

        private static readonly long[] _mMaxmask = new long[]
        {
            0x0000000000000001L, 0x0000000000000003L, 0x0000000000000007L, 0x000000000000000FL,
            0x000000000000001FL, 0x000000000000003FL, 0x000000000000007FL, 0x00000000000000FFL, 
            0x00000000000001FFL, 0x00000000000003FFL, 0x00000000000007FFL, 0x0000000000000FFFL, 
            0x0000000000001FFFL, 0x0000000000003FFFL, 0x0000000000007FFFL, 0x000000000000FFFFL,
            0x000000000001FFFFL, 0x000000000003FFFFL, 0x000000000007FFFFL, 0x00000000000FFFFFL, 
            0x00000000001FFFFFL, 0x00000000003FFFFFL, 0x00000000007FFFFFL, 0x0000000000FFFFFFL, 
            0x0000000001FFFFFFL, 0x0000000003FFFFFFL, 0x0000000007FFFFFFL, 0x000000000FFFFFFFL,
            0x000000001FFFFFFFL, 0x000000003FFFFFFFL, 0x000000007FFFFFFFL, 0x00000000FFFFFFFFL, 
            0x00000001FFFFFFFFL, 0x00000003FFFFFFFFL, 0x00000007FFFFFFFFL, 0x0000000FFFFFFFFFL, 
            0x0000001FFFFFFFFFL, 0x0000003FFFFFFFFFL, 0x0000007FFFFFFFFFL, 0x000000FFFFFFFFFFL,
            0x000001FFFFFFFFFFL, 0x000003FFFFFFFFFFL, 0x000007FFFFFFFFFFL, 0x00000FFFFFFFFFFFL, 
            0x00001FFFFFFFFFFFL, 0x00003FFFFFFFFFFFL, 0x00007FFFFFFFFFFFL, 0x0000FFFFFFFFFFFFL, 
            0x0001FFFFFFFFFFFFL, 0x0003FFFFFFFFFFFFL, 0x0007FFFFFFFFFFFFL, 0x000FFFFFFFFFFFFFL,
            0x001FFFFFFFFFFFFFL, 0x003FFFFFFFFFFFFFL, 0x007FFFFFFFFFFFFFL, 0x00FFFFFFFFFFFFFFL, 
            0x01FFFFFFFFFFFFFFL, 0x03FFFFFFFFFFFFFFL, 0x07FFFFFFFFFFFFFFL, 0x0FFFFFFFFFFFFFFFL, 
            0x1FFFFFFFFFFFFFFFL, 0x3FFFFFFFFFFFFFFFL, 0x7FFFFFFFFFFFFFFFL, unchecked((long)0xFFFFFFFFFFFFFFFFL)
        };

        private static readonly int[] _mIBY64 = new int[]
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 2
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 3
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 7
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 8
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 9
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 10
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 11
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 12
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 13
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 14
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 15
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 16
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 17
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 18
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 19
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 20
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 21
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 22
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 // 23
        };
        #endregion

        #region Constructors
        /// <summary>
        /// Construct a random element over the field <c>gf2n</c>, using the specified source of randomness
        /// </summary>
        /// 
        /// <param name="Gf2n">The field</param>
        /// <param name="SecRnd">The source of randomness</param>
        public GF2nONBElement(GF2nONBField Gf2n, IRandom SecRnd)
        {
            m_Field = Gf2n;
            m_Degree = m_Field.Degree;
            m_Length = Gf2n.GetONBLength();
            m_Bit = Gf2n.GetONBBit();
            m_Pol = new long[m_Length];

            if (m_Length > 1)
            {
                for (int j = 0; j < m_Length - 1; j++)
                    m_Pol[j] = SecRnd.NextLong(); //ju next long?
                
                long last = SecRnd.Next();
                m_Pol[m_Length - 1] = IntUtils.URShift(last, (MAXLONG - m_Bit));
            }
            else
            {
                m_Pol[0] = SecRnd.NextLong();
                m_Pol[0] = IntUtils.URShift(m_Pol[0], (MAXLONG - m_Bit));
            }
        }

        /// <summary>
        /// Construct a new GF2nONBElement from its encoding
        /// </summary>
        /// 
        /// <param name="Gf2n">The field</param>
        /// <param name="Encoded">The encoded element</param>
        public GF2nONBElement(GF2nONBField Gf2n, byte[] Encoded)
        {
            m_Field = Gf2n;
            m_Degree = m_Field.Degree;
            m_Length = Gf2n.GetONBLength();
            m_Bit = Gf2n.GetONBBit();
            m_Pol = new long[m_Length];
            Assign(Encoded);
        }

        /// <summary>
        /// Construct the element of the field <c>Gf2n</c> with the specified value <c>Value</c>
        /// </summary>
        /// 
        /// <param name="Gf2n">The field</param>
        /// <param name="Value">The value represented by a BigInteger</param>
        public GF2nONBElement(GF2nONBField Gf2n, BigInteger Value)
        {
            m_Field = Gf2n;
            m_Degree = m_Field.Degree;
            m_Length = Gf2n.GetONBLength();
            m_Bit = Gf2n.GetONBBit();
            m_Pol = new long[m_Length];
            Assign(Value);
        }

        /// <summary>
        /// Construct the element of the field <c>Gf2n</c> with the specified value <c>Value</c>
        /// </summary>
        /// 
        /// <param name="Gf2n">The field</param>
        /// <param name="Value">The value in ONB representation</param>
        private GF2nONBElement(GF2nONBField Gf2n, long[] Value)
        {
            m_Field = Gf2n;
            m_Degree = m_Field.Degree;
            m_Length = Gf2n.GetONBLength();
            m_Bit = Gf2n.GetONBBit();
            m_Pol = Value;
        }

        /// <summary>
        /// Copy the field values from another GF2nONBElement instance
        /// </summary>
        /// 
        /// <param name="Gf2n">The GF2nONBElement to copy</param>
        public GF2nONBElement(GF2nONBElement Gf2n)
        {

            m_Field = Gf2n.m_Field;
            m_Degree = m_Field.Degree;
            m_Length = ((GF2nONBField)m_Field).GetONBLength();
            m_Bit = ((GF2nONBField)m_Field).GetONBBit();
            m_Pol = new long[m_Length];
            Assign(Gf2n.GetElement());
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Multiplicatively invert of this element (overwrite <c>this</c>)
        /// </summary>
        public void InvertThis()
        {
            if (IsZero())
                throw new ArithmeticException();

            int r = 31; // m_Degree kann nur 31 Bits lang sein!!!

            // Bitlaenge von m_Degree:
            for (bool found = false; !found && r >= 0; r--)
            {
                if (((m_Degree - 1) & _mBitmask[r]) != 0)
                    found = true;
            }
            r++;

            GF2nElement m = Zero((GF2nONBField)m_Field);
            GF2nElement n = new GF2nONBElement(this);
            int k = 1;

            for (int i = r - 1; i >= 0; i--)
            {
                m = (GF2nElement)n.Clone();
                for (int j = 1; j <= k; j++)
                    m.SquareThis();

                n.MultiplyThisBy(m);

                k <<= 1;
                if (((m_Degree - 1) & _mBitmask[i]) != 0)
                {
                    n.SquareThis();
                    n.MultiplyThisBy(this);
                    k++;
                }
            }
            n.SquareThis();
        }

        /// <summary>
        /// Create the one element
        /// </summary>
        /// 
        /// <param name="Gf2n">The finite field</param>
        /// 
        /// <returns>Returns the one element in the given finite field</returns>
        public static GF2nONBElement One(GF2nONBField Gf2n)
        {
            int mLength = Gf2n.GetONBLength();
            long[] polynomial = new long[mLength];

            // fill m_Degree coefficients with one's
            for (int i = 0; i < mLength - 1; i++)
                polynomial[i] = unchecked((long)0xffffffffffffffffL);
            
            polynomial[mLength - 1] = _mMaxmask[Gf2n.GetONBBit() - 1];

            return new GF2nONBElement(Gf2n, polynomial);
        }

        /// <summary>
        /// Reverses the bit-order in this element(according to 1363). This is a hack!
        /// </summary>
        public void ReverseOrder()
        {
            m_Pol = GetElementReverseOrder();
        }

        /// <summary>
        /// Create the zero element
        /// </summary>
        /// 
        /// <param name="Gf2n">The finite field</param>
        /// 
        /// <returns>The zero element in the given finite field</returns>
        public static GF2nONBElement Zero(GF2nONBField Gf2n)
        {
            long[] polynomial = new long[Gf2n.GetONBLength()];
            return new GF2nONBElement(Gf2n, polynomial);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Assigns to this element the value <c>Value</c>
        /// </summary>
        /// 
        /// <param name="Value">The value represented by a BigInteger</param>
        private void Assign(BigInteger Value)
        {
            Assign(Value.ToByteArray());
        }

        /// <summary>
        /// Assigns to this element the value <c>val</c>. First: inverting the order of val into reversed[]
        /// </summary>
        /// 
        /// <param name="Value">The value in ONB representation</param>
        private void Assign(byte[] Value)
        {
            int j;
            m_Pol = new long[m_Length];

            for (j = 0; j < Value.Length; j++)
                m_Pol[IntUtils.URShift(j, 3)] |= (Value[Value.Length - 1 - j] & 0x00000000000000ffL) << ((j & 0x07) << 3);
        }

        /// <summary>
        /// Assigns to this element the value <c>Value</c>
        /// </summary>
        /// 
        /// <param name="Value">The value in ONB representation</param>
        private void Assign(long[] Value)
        {
            Array.Copy(Value, 0, m_Pol, 0, m_Length);
        }

        /// <summary>
        /// Returns this element in its ONB representation
        /// </summary>
        /// 
        /// <returns>The element in its ONB representation</returns>
        private long[] GetElement()
        {

            long[] result = new long[m_Pol.Length];
            Array.Copy(m_Pol, 0, result, 0, m_Pol.Length);

            return result;
        }

        /// <summary>
        /// Returns the ONB representation of this element. The Bit-Order is exchanged (according to 1363)!
        /// </summary>
        /// 
        /// <returns>Returns this element in its representation and reverse bit-order</returns>
        private long[] GetElementReverseOrder()
        {
            long[] result = new long[m_Pol.Length];
            for (int i = 0; i < m_Degree; i++)
            {
                if (TestBit(m_Degree - i - 1))
                    result[IntUtils.URShift(i, 6)] |= _mBitmask[i & 0x3f];
            }
            return result;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compute the sum of this element and <c>Addend</c>.
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        /// 
        /// <returns>Returns <c>this + other</c></returns>
        public override IGFElement Add(IGFElement Addend)
        {
            GF2nONBElement result = new GF2nONBElement(this);
            result.AddToThis(Addend);
            return result;
        }

        /// <summary>
        /// Compute <c>this + addend</c> (overwrite <c>this</c>)
        /// </summary>
        /// 
        /// <param name="Addend">The addend</param>
        public override void AddToThis(IGFElement Addend)
        {
            if (!(Addend is GF2nONBElement))
                throw new Exception();
            if (!m_Field.Equals(((GF2nONBElement)Addend).m_Field))
                throw new Exception();

            for (int i = 0; i < m_Length; i++)
                m_Pol[i] ^= ((GF2nONBElement)Addend).m_Pol[i];
        }

        /// <summary>
        /// Assigns to this element the one element
        /// </summary>
        public override void AssignOne()
        {
            // fill m_Degree coefficients with one's
            for (int i = 0; i < m_Length - 1; i++)
                m_Pol[i] = unchecked((long)0xffffffffffffffffL);

            m_Pol[m_Length - 1] = _mMaxmask[m_Bit - 1];
        }

        /// <summary>
        /// Assigns to this element the zero element
        /// </summary>
        public override void AssignZero()
        {
            m_Pol = new long[m_Length];
        }

        /// <summary>
        /// Create a new GF2nONBElement by cloning this GF2nPolynomialElement
        /// </summary>
        /// 
        /// <returns>Returns a copy of this element</returns>
        public override Object Clone()
        {
            return new GF2nONBElement(this);
        }

        /// <summary>
        /// Compare this element with another object
        /// </summary>
        /// 
        /// <param name="Obj">The object for comprison</param>
        /// 
        /// <returns>Returns <c>true</c> if the two objects are equal, <c>false</c> otherwise</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is GF2nONBElement))
            {
                return false;
            }

            GF2nONBElement otherElem = (GF2nONBElement)Obj;

            for (int i = 0; i < m_Length; i++)
            {
                if (m_Pol[i] != otherElem.m_Pol[i])
                {
                    return false;
                }
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
            return m_Pol.GetHashCode();
        }

        /// <summary>
        /// Compute <c>this</c> element + 1
        /// </summary>
        /// 
        /// <returns>Returns <c>this</c> + 1</returns>
        public override GF2nElement Increase()
        {
            GF2nONBElement result = new GF2nONBElement(this);
            result.IncreaseThis();
            return result;
        }

        /// <summary>
        /// Increases this element by one
        /// </summary>
        public override void IncreaseThis()
        {
            AddToThis(One((GF2nONBField)m_Field));
        }

        /// <summary>
        /// Compute the multiplicative inverse of this element
        /// </summary>
        /// 
        /// <returns>Returns <c>this^-1</c> (newly created)</returns>
        public override IGFElement Invert()
        {
            GF2nONBElement result = new GF2nONBElement(this);
            result.InvertThis();

            return result;
        }

        /// <summary>
        /// Tests if the GF2nPolynomialElement has 'one' as value
        /// </summary>
        /// 
        /// <returns>Returns true if <c>this</c> equals one (this == 1)</returns>
        public override bool IsOne()
        {
            bool result = true;

            for (int i = 0; i < m_Length - 1 && result; i++)
                result = result && ((m_Pol[i] & unchecked((long)0xFFFFFFFFFFFFFFFFL)) == unchecked((long)0xFFFFFFFFFFFFFFFFL));

            if (result)
                result = result && ((m_Pol[m_Length - 1] & _mMaxmask[m_Bit - 1]) == _mMaxmask[m_Bit - 1]);

            return result;
        }

        /// <summary>
        /// Checks whether this element is zero
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if <c>this</c> is the zero element</returns>
        public override bool IsZero()
        {
            bool result = true;

            for (int i = 0; i < m_Length && result; i++)
                result = result && ((m_Pol[i] & unchecked((long)0xFFFFFFFFFFFFFFFFL)) == 0);

            return result;
        }

        /// <summary>
        /// Compute the product of this element and <c>factor</c>
        /// </summary>
        /// 
        /// <param name="Factor">he factor</param>
        /// 
        /// <returns>Returns <c>this * factor</c> </returns>
        public override IGFElement Multiply(IGFElement Factor)
        {
            GF2nONBElement result = new GF2nONBElement(this);
            result.MultiplyThisBy(Factor);
            return result;
        }

        /// <summary>
        /// Compute <c>this * factor</c> (overwrite <c>this</c>).
        /// </summary>
        /// 
        /// <param name="Factor">The factor</param>
        public override void MultiplyThisBy(IGFElement Factor)
        {

            if (!(Factor is GF2nONBElement))
                throw new Exception("The elements have different" + " representation: not yet" + " implemented");
            if (!m_Field.Equals(((GF2nONBElement)Factor).m_Field))
                throw new Exception();

            if (Equals(Factor))
            {
                SquareThis();
            }
            else
            {

                long[] a = m_Pol;
                long[] b = ((GF2nONBElement)Factor).m_Pol;
                long[] c = new long[m_Length];
                int[][] m = ((GF2nONBField)m_Field).m_MultM;
                int degf, degb, s, fielda, fieldb, bita, bitb;
                degf = m_Length - 1;
                degb = m_Bit - 1;
                s = 0;

                long TWOTOMAXLONGM1 = _mBitmask[MAXLONG - 1];
                long TWOTODEGB = _mBitmask[degb];
                bool old, now;

                // the product c of a and b (a*b = c) is calculated in m_Degree cicles in every 
                // cicle one coefficient of c is calculated and stored k indicates the coefficient
                for (int k = 0; k < m_Degree; k++)
                {
                    s = 0;
                    for (int i = 0; i < m_Degree; i++)
                    {

                        fielda = _mIBY64[i];
                        bita = i & (MAXLONG - 1);
                        fieldb = _mIBY64[m[i][0]];
                        bitb = m[i][0] & (MAXLONG - 1);

                        if ((a[fielda] & _mBitmask[bita]) != 0)
                        {

                            if ((b[fieldb] & _mBitmask[bitb]) != 0)
                                s ^= 1;

                            if (m[i][1] != -1)
                            {
                                fieldb = _mIBY64[m[i][1]];
                                bitb = m[i][1] & (MAXLONG - 1);

                                if ((b[fieldb] & _mBitmask[bitb]) != 0)
                                    s ^= 1;
                            }
                        }
                    }

                    fielda = _mIBY64[k];
                    bita = k & (MAXLONG - 1);

                    if (s != 0)
                        c[fielda] ^= _mBitmask[bita];

                    // Circular shift of x and y one bit to the right, respectively
                    if (m_Length > 1)
                    {
                        old = (a[degf] & 1) == 1;

                        for (int i = degf - 1; i >= 0; i--)
                        {
                            now = (a[i] & 1) != 0;
                            a[i] = IntUtils.URShift(a[i], 1);
                            if (old)
                                a[i] ^= TWOTOMAXLONGM1;

                            old = now;
                        }
                        a[degf] = IntUtils.URShift(a[degf], 1);

                        if (old)
                            a[degf] ^= TWOTODEGB;

                        old = (b[degf] & 1) == 1;

                        for (int i = degf - 1; i >= 0; i--)
                        {
                            now = (b[i] & 1) != 0;
                            b[i] = IntUtils.URShift(b[i], 1);
                            if (old)
                                b[i] ^= TWOTOMAXLONGM1;

                            old = now;
                        }

                        b[degf] = IntUtils.URShift(b[degf], 1);

                        if (old)
                            b[degf] ^= TWOTODEGB;
                    }
                    else
                    {
                        old = (a[0] & 1) == 1;
                        a[0] = IntUtils.URShift(a[0], 1);

                        if (old)
                            a[0] ^= TWOTODEGB;

                        old = (b[0] & 1) == 1;
                        b[0] = IntUtils.URShift(b[0], 1);

                        if (old)
                            b[0] ^= TWOTODEGB;
                    }
                }
                Assign(c);
            }
        }

        /// <summary>
        /// Solves a quadratic equation
        /// <para>Let z^2 + z = <c>this</c>. Then this method returns z.</para>
        /// </summary>
        /// 
        /// <returns>Returns z with z^2 + z = <c>this</c></returns>
        public override  GF2nElement SolveQuadraticEquation()
        {
            if (Trace() == 1)
                throw new Exception();

            long TWOTOMAXLONGM1 = _mBitmask[MAXLONG - 1];
            long ZERO = 0L;
            long ONE = 1L;
            long[] p = new long[m_Length];
            long z = 0L;
            int j = 1;

            for (int i = 0; i < m_Length - 1; i++)
            {
                for (j = 1; j < MAXLONG; j++)
                {
                    if (!((((_mBitmask[j] & m_Pol[i]) != ZERO) && ((z & _mBitmask[j - 1]) != ZERO)) || (((m_Pol[i] & _mBitmask[j]) == ZERO) && ((z & _mBitmask[j - 1]) == ZERO))))
                        z ^= _mBitmask[j];
                }
                p[i] = z;

                if (((TWOTOMAXLONGM1 & z) != ZERO && (ONE & m_Pol[i + 1]) == ONE) || ((TWOTOMAXLONGM1 & z) == ZERO && (ONE & m_Pol[i + 1]) == ZERO))
                    z = ZERO;
                else
                    z = ONE;
            }

            int b = m_Degree & (MAXLONG - 1);
            long LASTLONG = m_Pol[m_Length - 1];

            for (j = 1; j < b; j++)
            {
                if (!((((_mBitmask[j] & LASTLONG) != ZERO) && ((_mBitmask[j - 1] & z) != ZERO)) || (((_mBitmask[j] & LASTLONG) == ZERO) && ((_mBitmask[j - 1] & z) == ZERO))))
                    z ^= _mBitmask[j];
            }
            p[m_Length - 1] = z;

            return new GF2nONBElement((GF2nONBField)m_Field, p);
        }

        /// <summary>
        /// Compute <c>this</c> element to the power of 2
        /// </summary>
        /// 
        /// <returns>Returns <c>this</c>^2</returns>
        public override GF2nElement Square()
        {
            GF2nONBElement result = new GF2nONBElement(this);
            result.SquareThis();

            return result;
        }

        /// <summary>
        /// Squares <c>this</c> element
        /// </summary>
        public override void SquareThis()
        {
            long[] pol = GetElement();
            int f = m_Length - 1;
            int b = m_Bit - 1;
            // Shift the coefficients one bit to the left.
            long TWOTOMAXLONGM1 = _mBitmask[MAXLONG - 1];
            bool old, now;
            old = (pol[f] & _mBitmask[b]) != 0;

            for (int i = 0; i < f; i++)
            {
                now = (pol[i] & TWOTOMAXLONGM1) != 0;
                pol[i] = pol[i] << 1;
                if (old)
                    pol[i] ^= 1;

                old = now;
            }
            now = (pol[f] & _mBitmask[b]) != 0;
            pol[f] = pol[f] << 1;
            if (old)
                pol[f] ^= 1;

            // Set the bit with index m_Degree to zero.
            if (now)
                pol[f] ^= _mBitmask[b + 1];

            Assign(pol);
        }

        /// <summary>
        /// Compute the square root of this element and return the result in a new GF2nElement
        /// </summary>
        /// 
        /// <returns>Returns <c>this^1/2</c> (newly created)</returns>
        public override  GF2nElement SquareRoot()
        {
            GF2nONBElement result = new GF2nONBElement(this);
            result.SquareRootThis();
            return result;
        }

        /// <summary>
        /// Compute the square root of this element
        /// </summary>
        public override void SquareRootThis()
        {
            long[] pol = GetElement();
            int f = m_Length - 1;
            int b = m_Bit - 1;
            // Shift the coefficients one bit to the right.
            long TWOTOMAXLONGM1 = _mBitmask[MAXLONG - 1];
            bool old, now;
            old = (pol[0] & 1) != 0;

            for (int i = f; i >= 0; i--)
            {
                now = (pol[i] & 1) != 0;
                pol[i] = IntUtils.URShift(pol[i], 1);

                if (old)
                {
                    if (i == f)
                        pol[i] ^= _mBitmask[b];
                    else
                        pol[i] ^= TWOTOMAXLONGM1;
                }
                old = now;
            }
            Assign(pol);
        }

        /// <summary>
        /// Checks whether the indexed bit of the bit representation is set
        /// <para>Note: GF2nElement currently stores its bits in reverse order</para>
        /// </summary>
        /// 
        /// <param name="Index">The index of the bit to test</param>
        /// 
        /// <returns>Returns <c>true</c> if the indexed bit is set</returns>
        public override bool TestBit(int Index)
        {
            if (Index < 0 || Index > m_Degree)
            {
                return false;
            }
            long test = m_Pol[IntUtils.URShift(Index, 6)] & _mBitmask[Index & 0x3f];
            return test != 0x0L;
        }

        /// <summary>
        /// Returns whether the rightmost bit of the bit representation is set. 
        /// This is needed for data conversion according to 1363.
        /// </summary>
        /// 
        /// <returns>Returns true if the rightmost bit of this element is set</returns>
        public override bool TestRightmostBit()
        {
            // due to the reverse bit order (compared to 1363) this method returns the value of the leftmost bit
            return (m_Pol[m_Length - 1] & _mBitmask[m_Bit - 1]) != 0L;
        }

        /// <summary>
        /// Converts this GF2nPolynomialElement to a byte[] according to 1363
        /// </summary>
        /// 
        /// <returns>Returns a byte[] representing the value of this GF2nPolynomialElement</returns>
        public override byte[] ToByteArray()
        {
            // ToDo this method does not reverse the bit-order as it should!
            int k = ((m_Degree - 1) >> 3) + 1;
            byte[] result = new byte[k];
            int i;

            for (i = 0; i < k; i++)
                result[k - i - 1] = (byte)(IntUtils.URShift((m_Pol[IntUtils.URShift(i, 3)] & (0x00000000000000ffL << ((i & 0x07) << 3))), ((i & 0x07) << 3)));
            
            return result;
        }

        /// <summary>
        /// Converts this GF2nPolynomialElement to an integer according to 1363
        /// </summary>
        /// 
        /// <returns>Returns a BigInteger representing the value of this GF2nPolynomialElement</returns>
        public override BigInteger ToFlexiBigInt()
        {
            // ToDo this method does not reverse the bit-order as it should!
            return new BigInteger(1, ToByteArray());
        }

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal radix in MSB-first order
        /// </summary>
        /// 
        /// <returns>Returns a String representing this Bitstrings value</returns>
        public override String ToString()
        {
            return ToString(16);
        }

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal or binary radix in MSB-first order
        /// </summary>
        /// 
        /// <param name="Radix">The radix to use (2 or 16, otherwise 2 is used)</param>
        /// 
        /// <returns>Returns a String representing this Bitstrings value.</returns>
        public override String ToString(int Radix)
        {
            String s = "";
            long[] a = GetElement();
            int b = m_Bit;

            if (Radix == 2)
            {
                for (int j = b - 1; j >= 0; j--)
                {
                    if ((a[a.Length - 1] & ((long)1 << j)) == 0)
                        s += "0";
                    else
                        s += "1";
                }

                for (int i = a.Length - 2; i >= 0; i--)
                {
                    for (int j = MAXLONG - 1; j >= 0; j--)
                    {
                        if ((a[i] & _mBitmask[j]) == 0)
                            s += "0";
                        else
                            s += "1";
                    }
                }
            }
            else if (Radix == 16)
            {
                char[] HEX_CHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
                for (int i = a.Length - 1; i >= 0; i--)
                {
                    s += HEX_CHARS[(int)(a[i] >> 60) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 56) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 52) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 48) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 44) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 40) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 36) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 32) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 28) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 24) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 20) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 16) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 12) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 8) & 0x0f];
                    s += HEX_CHARS[(int)(a[i] >> 4) & 0x0f];
                    s += HEX_CHARS[(int)(a[i]) & 0x0f];
                    s += " ";
                }
            }
            return s;
        }

        /// <summary>
        /// Computes the trace of this element
        /// </summary>
        /// 
        /// <returns>Returns the trace of this element</returns>
        public override int Trace()
        {
            int result = 0;
            int max = m_Length - 1;

            for (int i = 0; i < max; i++)
            {
                for (int j = 0; j < MAXLONG; j++)
                {
                    if ((m_Pol[i] & _mBitmask[j]) != 0)
                        result ^= 1;
                }
            }

            int b = m_Bit;

            for (int j = 0; j < b; j++)
            {
                if ((m_Pol[max] & _mBitmask[j]) != 0)
                    result ^= 1;
            }

            return result;
        }
        #endregion
    }
}
