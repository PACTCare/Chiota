#region Directives
using System;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements the abstract class <c>Vector</c> for the case of vectors over the finite field GF(2). 
    /// <para>For the vector representation the array of type int[] is used, thus one element of the array holds 32 elements of the vector.</para>
    /// </summary>
    internal sealed class GF2Vector : Vector
    {
        #region Fields
        // holds the elements of this vector
        private int[] m_elements;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the int array representation of this vector
        /// </summary>
        public int[] VectorArray
        {
            get { return m_elements; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Construct the zero vector of the given length
        /// </summary>
        /// 
        /// <param name="Length">The length of the vector</param>
        public GF2Vector(int Length)
        {
            if (Length < 0)
                throw new ArithmeticException("Negative length.");

            this.Length = Length;
            m_elements = new int[(Length + 31) >> 5];
        }

        /// <summary>
        /// Construct a random GF2Vector of the given length
        /// </summary>
        /// 
        /// <param name="Length">The length of the vector</param>
        /// <param name="SecRnd">The source of randomness</param>
        public GF2Vector(int Length, IRandom SecRnd)
        {
            this.Length = Length;

            int size = (Length + 31) >> 5;
            m_elements = new int[size];

            // generate random elements
            for (int i = size - 1; i >= 0; i--)
                m_elements[i] = SecRnd.Next();

            // erase unused bits
            int r = Length & 0x1f;

            // erase unused bits
            if (r != 0)
                m_elements[size - 1] &= (1 << r) - 1;
        }

        /// <summary>
        /// Construct a random GF2Vector of the given length with the specified number of non-zero coefficients
        /// </summary>
        /// 
        /// <param name="Length">The length of the vector</param>
        /// <param name="T">The number of non-zero coefficients</param>
        /// <param name="SecRnd">The source of randomness</param>
        public GF2Vector(int Length, int T, IRandom SecRnd)
        {
            if (T > Length)
                throw new ArithmeticException("The hamming weight is greater than the length of vector.");
            
            this.Length = Length;

            int size = (Length + 31) >> 5;
            m_elements = new int[size];

            int[] help = new int[Length];
            for (int i = 0; i < Length; i++)
                help[i] = i;

            int m = Length;
            for (int i = 0; i < T; i++)
            {
                int j = RandomDegree.NextInt(SecRnd, m);
                SetBit(help[j]);
                m--;
                help[j] = help[m];
            }
        }

        /// <summary>
        /// Construct a GF2Vector of the given length and with elements from the given array.
        /// <para>The array is copied and unused bits are masked out.</para>
        /// </summary>
        /// 
        /// <param name="Length">The length of the vector</param>
        /// <param name="V">The element array</param>
        public GF2Vector(int Length, int[] V)
        {
            if (Length < 0)
                throw new ArithmeticException("GF2Vector: negative length!");

            this.Length = Length;

            int size = (Length + 31) >> 5;

            if (V.Length != size)
                throw new ArithmeticException("GF2Vector: length mismatch!");

            this.m_elements = IntUtils.DeepCopy(V);

            int r = Length & 0x1f;

            // erase unused bits
            if (r != 0)
                this.m_elements[size - 1] &= (1 << r) - 1;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// 
        /// <param name="G">The GF2Vector to copy</param>
        public GF2Vector(GF2Vector G)
        {
            this.Length = G.Length;
            this.m_elements = IntUtils.DeepCopy(G.m_elements);
        }

        /// <summary>
        /// Construct a new GF2Vector of the given length and with the given element array. 
        /// <para>The array is not changed and only a reference to the array is stored. No length checking is performed either.</para>
        /// </summary>
        /// 
        /// <param name="V">The element array</param>
        /// <param name="Length">The length of the vector</param>
        public GF2Vector(int[] V, int Length)
        {
            this.m_elements = V;
            this.Length = Length;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Return a new vector consisting of the elements of this vector with the indices given by the set <c>SetJ</c>
        /// </summary>
        /// 
        /// <param name="SetJ">The set of indices of elements to extract</param>
        /// 
        /// <returns>Return the new GF2Vector <c>[SetJ[0], SetJ[1], ..., SetJ[#SetJ-1]]</c></returns>
        public GF2Vector ExtractVector(int[] SetJ)
        {
            int k = SetJ.Length;
            if (SetJ[k - 1] > Length)
                throw new ArithmeticException("invalid index set");

            GF2Vector result = new GF2Vector(k);

            for (int i = 0; i < k; i++)
            {
                int e = m_elements[SetJ[i] >> 5] & (1 << (SetJ[i] & 0x1f));
                if (e != 0)
                    result.m_elements[i >> 5] |= 1 << (i & 0x1f);
            }

            return result;
        }

        /// <summary>
        /// Return a new vector consisting of the first <c>K</c> elements of this vector
        /// </summary>
        /// 
        /// <param name="K">The number of elements to extract</param>
        /// 
        /// <returns>Returns a new GF2Vector consisting of the first <c>K</c> elements of this vector</returns>
        public GF2Vector ExtractLeftVector(int K)
        {
            if (K > Length)
                throw new ArithmeticException("invalid length");

            if (K == Length)
                return new GF2Vector(this);

            GF2Vector result = new GF2Vector(K);

            int q = K >> 5;
            int r = K & 0x1f;

            Array.Copy(m_elements, 0, result.m_elements, 0, q);
            if (r != 0)
                result.m_elements[q] = m_elements[q] & ((1 << r) - 1);

            return result;
        }

        /// <summary>
        /// Return a new vector consisting of the last <c>k</c> elements of this vector
        /// </summary>
        /// 
        /// <param name="K">The number of elements to extract</param>
        /// 
        /// <returns>Returns a new GF2Vector consisting of the last <c>K</c> elements of this vector</returns>
        public GF2Vector ExtractRightVector(int K)
        {
            if (K > base.Length)
                throw new ArithmeticException("invalid length");

            if (K == base.Length)
                return new GF2Vector(this);

            GF2Vector result = new GF2Vector(K);

            int q = (base.Length - K) >> 5;
            int r = (base.Length - K) & 0x1f;
            int length = (K + 31) >> 5;
            int ind = q;

            // if words have to be shifted
            if (r != 0)
            {
                // process all but last word
                for (int i = 0; i < length - 1; i++)
                    result.m_elements[i] = (IntUtils.URShift(m_elements[ind++], r)) | (m_elements[ind] << (32 - r));
                // process last word
                result.m_elements[length - 1] = IntUtils.URShift(m_elements[ind++], r);
                if (ind < m_elements.Length)
                    result.m_elements[length - 1] |= m_elements[ind] << (32 - r);
            }
            else
            {
                // no shift necessary
                Array.Copy(m_elements, q, result.m_elements, 0, length);
            }

            return result;
        }

        /// <summary>
        /// Return the value of the bit of this vector at the specified index
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        /// 
        /// <returns>Returns the value of the bit (0 or 1)</returns>
        public int GetBit(int Index)
        {
            if (Index >= Length)
                throw new Exception();
            
            int q = Index >> 5;
            int r = Index & 0x1f;

            return IntUtils.URShift((m_elements[q] & (1 << r)), r);
        }

        /// <summary>
        /// Return the Hamming weight of this vector, i.e., compute the number of units of this vector
        /// </summary>
        /// 
        /// <returns>Returns the Hamming weight of this vector</returns>
        public int HammingWeight()
        {
            int weight = 0;
            for (int i = 0; i < m_elements.Length; i++)
            {
                int e = m_elements[i];
                for (int j = 0; j < 32; j++)
                {
                    int b = e & 1;
                    if (b != 0)
                        weight++;
                    
                    e = IntUtils.URShift(e, 1);
                }
            }

            return weight;
        }

        /// <summary>
        /// Construct a new GF2Vector with the given length out of the encoded vector
        /// </summary>
        /// 
        /// <param name="Length">The length of the vector</param>
        /// <param name="EncVec">The encoded vector</param>
        /// 
        /// <returns>Returns the decoded vector</returns>
        public static GF2Vector OS2VP(int Length, byte[] EncVec)
        {
            if (Length < 0)
                throw new ArithmeticException("negative length");

            int byteLen = (Length + 7) >> 3;

            if (EncVec.Length > byteLen)
                throw new ArithmeticException("length mismatch");

            return new GF2Vector(Length, LittleEndian.ToIntArray(EncVec));
        }

        /// <summary>
        /// Set the coefficient at the given index to 1. If the index is out of bounds, do nothing
        /// </summary>
        /// 
        /// <param name="Index">The index of the coefficient to set</param>
        public void SetBit(int Index)
        {
            if (Index >= Length)
                throw new Exception();
            
            m_elements[Index >> 5] |= 1 << (Index & 0x1f);
        }

        /// <summary>
        /// Rewrite this vector as a vector over <c>GF(2^m)</c> with <c>t</c> elements
        /// </summary>
        /// 
        /// <param name="Field">The finite field <c>GF(2<sup>m</sup>)</c></param>
        /// 
        /// <returns>Returns the converted vector over <c>GF(2<sup>m</sup>)</c></returns>
        public GF2mVector ToExtensionFieldVector(GF2mField Field)
        {
            int m = Field.Degree;
            if ((Length % m) != 0)
                throw new ArithmeticException("GF2Vector: Conversion is impossible!");

            int t = Length / m;
            int[] result = new int[t];
            int count = 0;
            for (int i = t - 1; i >= 0; i--)
            {
                for (int j = Field.Degree - 1; j >= 0; j--)
                {
                    int q = IntUtils.URShift(count, 5);
                    int r = count & 0x1f;

                    int e = (IntUtils.URShift(m_elements[q], r)) & 1;
                    if (e == 1)
                        result[i] ^= 1 << j;
                    
                    count++;
                }
            }
            return new GF2mVector(Field, result);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Adds another GF2Vector to this vector
        /// </summary>
        /// 
        /// <param name="V">The GF2Vector to add</param>
        /// 
        /// <returns>Returns <c>this + V</c></returns>
        public override Vector Add(Vector V)
        {
            if (!(V is GF2Vector))
                throw new ArithmeticException("GF2Vector: Vector is not defined over GF(2)!");

            GF2Vector otherVec = (GF2Vector)V;
            if (Length != otherVec.Length)
                throw new ArithmeticException("GF2Vector: Length mismatch!");

            int[] vec = IntUtils.DeepCopy(((GF2Vector)V).m_elements);

            for (int i = vec.Length - 1; i >= 0; i--)
                vec[i] ^= m_elements[i];

            return new GF2Vector(Length, vec);
        }

        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (!(Obj is GF2Vector))
                return false;
            GF2Vector otherVec = (GF2Vector)Obj;
            if (Length != otherVec.Length)
                return false;
            if (!Compare.IsEqual(m_elements, otherVec.m_elements))
                return false;

            return true;
        }

        /// <summary>
        /// Encode this vector as byte array
        /// </summary>
        /// 
        /// <returns>Returns the encoded vector</returns>
        public override byte[] GetEncoded()
        {
            int byteLen = (Length + 7) >> 3;
            return LittleEndian.ToByteArray(m_elements, byteLen);
        }
        
        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = Length * 31;
            hash += m_elements.GetHashCode();

            return hash;
        }

        /// <summary>
        /// Get: Return whether this is the zero vector (i.e., all elements are zero)
        /// </summary>
        /// <returns></returns>
        public override bool IsZero()
        {
            for (int i = m_elements.Length - 1; i >= 0; i--)
            {
                if (m_elements[i] != 0)
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Multiply this vector with a permutation
        /// </summary>
        /// 
        /// <param name="P">The permutation</param>
        /// 
        /// <returns>Returns <c>this*p = p*this</c></returns>
        public override Vector Multiply(Permutation P)
        {
            int[] pVec = P.GetVector();
            if (Length != pVec.Length)
                throw new ArithmeticException("GF2Vector: Length mismatch!");

            GF2Vector result = new GF2Vector(Length);

            for (int i = 0; i < pVec.Length; i++)
            {
                int e = m_elements[pVec[i] >> 5] & (1 << (pVec[i] & 0x1f));
                if (e != 0)
                    result.m_elements[i >> 5] |= 1 << (i & 0x1f);
            }

            return result;
        }

        /// <summary>
        /// Returns a string representing this Bitstrings value using hexadecimal radix in MSB-first order
        /// </summary>
        /// 
        /// <returns>Returns a String representing this Bitstrings value</returns>
        public override String ToString()
        {
            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < Length; i++)
            {
                if ((i != 0) && ((i & 0x1f) == 0))
                {
                    buf.Append(' ');
                }
                int q = i >> 5;
                int r = i & 0x1f;
                int bit = m_elements[q] & (1 << r);
                if (bit == 0)
                {
                    buf.Append('0');
                }
                else
                {
                    buf.Append('1');
                }
            }
            return buf.ToString();
        }
        #endregion
    }
}
