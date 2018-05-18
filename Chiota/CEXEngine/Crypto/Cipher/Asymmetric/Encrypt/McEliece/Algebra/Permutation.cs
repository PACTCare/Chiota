#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements permutations of the set {0,1,...,n-1} for some given n &gt; 0.
    /// <para>i.e., ordered sequences containing each number <c>m</c> (<c>0 &lt;= m &lt; n</c>) once and only once.</para>
    /// </summary>
    internal sealed class Permutation
    {
        #region Fields
        private int[] m_perm;
        #endregion

        #region Constructor
        /// <summary>
        /// Create the identity permutation of the given size
        /// </summary>
        /// 
        /// <param name="N">The size of the permutation</param>
        public Permutation(int N)
        {
            if (N <= 0)
                throw new ArgumentException("N is an invalid length!");

            m_perm = new int[N];
            for (int i = N - 1; i >= 0; i--)
                m_perm[i] = i;
        }

        /// <summary>
        /// Create a permutation using the given permutation vector
        /// </summary>
        /// 
        /// <param name="Perm">The permutation vector</param>
        public Permutation(int[] Perm)
        {
            if (!IsPermutation(Perm))
                throw new ArgumentException("Permutation: Array is not a permutation vector!");

            this.m_perm = IntUtils.DeepCopy(Perm);
        }
        
        /// <summary>
        /// Create a permutation using an encoded permutation
        /// </summary>
        /// 
        /// <param name="Encoded">The encoded permutation</param>
        public Permutation(byte[] Encoded)
        {
            if (Encoded.Length <= 4)
                throw new ArgumentException("Permutation: Invalid encoding!");

            int n = LittleEndian.OctetsToInt(Encoded, 0);
            int size = BigMath.CeilLog256(n - 1);

            if (Encoded.Length != 4 + n * size)
                throw new ArgumentException("Permutation: Invalid encoding!");

            m_perm = new int[n];
            for (int i = 0; i < n; i++)
                m_perm[i] = LittleEndian.OctetsToInt(Encoded, 4 + i * size, size);

            if (!IsPermutation(m_perm))
                throw new ArgumentException("Permutation: Invalid encoding!");
        }

        /// <summary>
        /// Create a random permutation of the given size
        /// </summary>
        /// 
        /// <param name="N">The size of the permutation</param>
        /// <param name="SecRnd">The source of randomness</param>
        public Permutation(int N, IRandom SecRnd)
        {
            if (N <= 0)
                throw new ArgumentException("Permutation: Invalid length!");

            m_perm = new int[N];
            int[] help = new int[N];

            for (int i = 0; i < N; i++)
                help[i] = i;

            int k = N;
            for (int j = 0; j < N; j++)
            {
                int i = RandomDegree.NextInt(SecRnd, k);
                k--;
                m_perm[j] = help[i];
                help[i] = help[k];
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Clear()
        {
            if (m_perm != null)
                Array.Clear(m_perm, 0, m_perm.Length);
        }

        /// <summary>
        /// Compute the inverse permutation <c>P pow -1</c>
        /// </summary>
        /// 
        /// <returns>Returns <c>this pow -1</c></returns>
        public Permutation ComputeInverse()
        {
            Permutation result = new Permutation(m_perm.Length);
            for (int i = m_perm.Length - 1; i >= 0; i--)
                result.m_perm[m_perm[i]] = i;

            return result;
        }

        /// <summary>
        /// Encode this permutation as byte array
        /// </summary>
        /// 
        /// <returns>The encoded permutation</returns>
        public byte[] GetEncoded()
        {
            int n = m_perm.Length;
            int size = BigMath.CeilLog256(n - 1);
            byte[] result = new byte[4 + n * size];
            LittleEndian.IntToOctets(n, result, 0);

            for (int i = 0; i < n; i++)
                LittleEndian.IntToOctets(m_perm[i], result, 4 + i * size, size);
            
            return result;
        }

        /// <summary>
        /// The permutation vector <c>(perm(0),perm(1),...,perm(n-1))</c>
        /// </summary>
        /// 
        /// <returns>The permutation vector</returns>
        public int[] GetVector()
        {
            return IntUtils.DeepCopy(m_perm);
        }

        /// <summary>
        /// Compute the product of this permutation and another permutation
        /// </summary>
        /// 
        /// <param name="p">The other permutation</param>
        /// 
        /// <returns>Returns <c>this * P</c></returns>
        public Permutation RightMultiply(Permutation p)
        {
            if (p.m_perm.Length != m_perm.Length)
                throw new ArgumentException("length mismatch");
            
            Permutation result = new Permutation(m_perm.Length);
            for (int i = m_perm.Length - 1; i >= 0; i--)
                result.m_perm[i] = m_perm[p.m_perm[i]];
            
            return result;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Checks if given object is equal to this permutation
        /// </summary>
        /// 
        /// <param name="Obj">The object to compare this with</param>
        /// 
        /// <returns>Returns false whenever the given object is not equl to this</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null)
                return false;
            if (!(Obj is Permutation))
                return false;

            Permutation otherPerm = (Permutation)Obj;

            return Compare.IsEqual(m_perm, otherPerm.m_perm);
        }

        /// <summary>
        /// Returns the hash code of this permutation
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return ArrayUtils.GetHashCode(m_perm);
        }

        /// <summary>
        /// Creates a human readable form of the permutation
        /// </summary>
        /// 
        /// <returns>Returns the permutation in readable form</returns>
        public override String ToString()
        {
            String result = "[" + m_perm[0];
            for (int i = 1; i < m_perm.Length; i++)
                result += ", " + m_perm[i];

            result += "]";

            return result;
        }
        #endregion

        #region Private Methods
        private bool IsPermutation(int[] Perm)
        {
            int n = Perm.Length;
            bool[] onlyOnce = new bool[n];

            for (int i = 0; i < n; i++)
            {
                if ((Perm[i] < 0) || (Perm[i] >= n) || onlyOnce[Perm[i]])
                    return false;
                
                onlyOnce[Perm[i]] = true;
            }

            return true;
        }
        #endregion
    }
}
