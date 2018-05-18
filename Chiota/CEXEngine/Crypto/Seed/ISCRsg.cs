#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Implementation Details:
// An implementation of a pseudo random generator.
// XSPRsg:  XorShift+random seed generator
// Written by John Underhill, June 1, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// ISCRsg: Generates seed material using an ISAAC random number generator.
    /// <para>A high speed, cryptographically secure pseudo random provider.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of getting a seed value:</description>
    /// <code>
    /// using (ISCRsg gen = new ISCRsg(Seed))
    ///     gen.GetSeed(Output);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng"/>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>ISAAC a fast cryptographic <a href="http://www.burtleburtle.net/bob/rand/isaacafa.html">Random Number Generator</a>.</description></item>
    /// <item><description>Rossettacode <a href="http://rosettacode.org/wiki/The_ISAAC_Cipher">Example implementations</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class ISCRsg : ISeed
    {
       #region Constants
        private const string ALG_NAME = "ISCRsg";
        private const int SIZE32 = 4;
	    private const int SIZE64 = 8;
	    private const int MSIZE = 1 << SIZE64;
	    private const int MASK = (MSIZE - 1) << 2;
        private const int GDNR = unchecked((int)0x9e3779b9); // golden ratio
        #endregion

        #region Fields
        private int m_accululator = 0;
        private int m_cycCounter = 0;
        private bool m_isDisposed = false;
        private int m_lstResult = 0;
        private int[] m_rndResult = new int[MSIZE];
        private uint m_rslCounter = 0;
        private int[] m_wrkBuffer = new int[MSIZE];
        #endregion

        #region Properties
        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public SeedGenerators Enumeral
        {
            get { return SeedGenerators.ISCRsg; }
        }

        /// <summary>
        /// Algorithm name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class using the EntropyPool to provide a seed value.
        /// <para>Seeds the generator with 1024 bytes from the pool.</para>
        /// </summary>
        public ISCRsg() 
        {
            // max pool draw is 1024 bytes
            byte[] rnd = new byte[MSIZE * 4];
            new EntropyPool().GetBytes(rnd);
            m_rndResult = new int[MSIZE];
            Buffer.BlockCopy(rnd, 0, m_rndResult, 0, MSIZE * 4);
            Initialize(true);
        }

        /// <summary>
        /// Initialize this class using a seed value
        /// </summary>
        ///
        /// <param name="Seed">The initial state values; must be between 2 and 256, 32bit values</param>
        ///
        /// <exception cref="VTDev.Libraries.CEXEngine.CryptoException.CryptoRandomException">Thrown if an invalid seed size is used</exception>
        public ISCRsg(int[] Seed)
        {
            if (Seed.Length < 1 && Seed.Length > 256)
                throw new CryptoRandomException("ISCRsg:CTor", "The seed array length must be between 1 and 256 int32 values!");

            int len = Seed.Length > MSIZE ? MSIZE : Seed.Length;
            Buffer.BlockCopy(Seed, 0, m_rndResult, 0, len * SIZE32);
            Initialize(true);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">The destination array</param>
        public void GetBytes(byte[] Output)
        {
            int offset = 0;
            int X;
            int len = sizeof(int);

            while (offset < Output.Length)
            {
                X = Next();

                if (Output.Length - offset < len)
                    len = Output.Length - offset;

                Buffer.BlockCopy(IntUtils.IntToBytes(X), 0, Output, offset, len);
                offset += len;
            }
        }

        /// <summary>
        /// Get a pseudo random seed byte array
        /// </summary>
        /// 
        /// <param name="Size">The size of the seed returned; up to a maximum of 1024 bytes</param>
        /// 
        /// <returns>A pseudo random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];
            GetBytes(data);
            return data;
        }

        /// <summary>
        /// initializes the generator with new state
        /// </summary>
        /// 
        /// <param name="MixState">Mix with the initial state values</param>
        public void Initialize(bool MixState)
        {
            int ctr = 0;
            int A, B, C, D, E, F, G, H;
            A = B = C = D = E = F = G = H = GDNR;

            Mix(ref A, ref B, ref C, ref D, ref E, ref F, ref G, ref H);
            Mix(ref A, ref B, ref C, ref D, ref E, ref F, ref G, ref H);
            Mix(ref A, ref B, ref C, ref D, ref E, ref F, ref G, ref H);
            Mix(ref A, ref B, ref C, ref D, ref E, ref F, ref G, ref H);

            while (ctr != MSIZE)
            {
                if (MixState)
                {
                    A += m_rndResult[ctr];
                    B += m_rndResult[ctr + 1];
                    C += m_rndResult[ctr + 2];
                    D += m_rndResult[ctr + 3];
                    E += m_rndResult[ctr + 4];
                    F += m_rndResult[ctr + 5];
                    G += m_rndResult[ctr + 6];
                    H += m_rndResult[ctr + 7];
                }

                Mix(ref A, ref B, ref C, ref D, ref E, ref F, ref G, ref H);

                m_wrkBuffer[ctr] = A;
                m_wrkBuffer[ctr + 1] = B;
                m_wrkBuffer[ctr + 2] = C;
                m_wrkBuffer[ctr + 3] = D;
                m_wrkBuffer[ctr + 4] = E;
                m_wrkBuffer[ctr + 5] = F;
                m_wrkBuffer[ctr + 6] = G;
                m_wrkBuffer[ctr + 7] = H;
                ctr += 8;
            }

            if (MixState)
            {
                // second pass makes all of seed affect all of mem
                ctr = 0;
                while (ctr != MSIZE)
                {
                    A += m_wrkBuffer[ctr];
                    B += m_wrkBuffer[ctr + 1];
                    C += m_wrkBuffer[ctr + 2];
                    D += m_wrkBuffer[ctr + 3];
                    E += m_wrkBuffer[ctr + 4];
                    F += m_wrkBuffer[ctr + 5];
                    G += m_wrkBuffer[ctr + 6];
                    H += m_wrkBuffer[ctr + 7];

                    Mix(ref A, ref B, ref C, ref D, ref E, ref F, ref G, ref H);

                    m_wrkBuffer[ctr] = A;
                    m_wrkBuffer[ctr + 1] = B;
                    m_wrkBuffer[ctr + 2] = C;
                    m_wrkBuffer[ctr + 3] = D;
                    m_wrkBuffer[ctr + 4] = E;
                    m_wrkBuffer[ctr + 5] = F;
                    m_wrkBuffer[ctr + 6] = G;
                    m_wrkBuffer[ctr + 7] = H;
                    ctr += 8;
                }
            }

            Generate();
        }

        /// <summary>
        /// Returns the next pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>A pseudo random 32 bit integer</returns>
        public int Next()
        {
            if (0 == m_rslCounter--)
            {
                Generate();
                m_rslCounter = MSIZE - 1;
            }
            return m_rndResult[m_rslCounter];
        }

        /// <summary>
        /// Reinitialize the internal state
        /// </summary>
        public void Reset()
        {
            Generate();
        }
        #endregion

        #region Private Methods
        private void Generate()
        {
	        const int SSZ = MSIZE / 2;
	        int i = 0;
	        int j = SSZ - 1;
	        int X, Y;
	        m_lstResult += ++m_cycCounter;

	        while (i != SSZ)
	        {
		        X = m_wrkBuffer[i];
		        m_accululator ^= m_accululator << 13;
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		        X = m_wrkBuffer[++i];
		        m_accululator ^= (int)((uint)m_accululator >> 6);
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		        X = m_wrkBuffer[++i];
		        m_accululator ^= m_accululator << 2;
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		        X = m_wrkBuffer[++i];
		        m_accululator ^= (int)((uint)m_accululator >> 16);
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;
		        ++i;
	        }

	        j = 0;
	        while (j != SSZ)
	        {
		        X = m_wrkBuffer[i];
		        m_accululator ^= m_accululator << 13;
		        m_accululator += m_wrkBuffer[j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		        X = m_wrkBuffer[++i];
		        m_accululator ^= (int)((uint)m_accululator >> 6);
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		        X = m_wrkBuffer[++i];
		        m_accululator ^= m_accululator << 2;
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;

		        X = m_wrkBuffer[++i];
		        m_accululator ^= (int)((uint)m_accululator >> 16);
		        m_accululator += m_wrkBuffer[++j];
		        m_wrkBuffer[i] = Y = m_wrkBuffer[(X & MASK) >> 2] + m_accululator + m_lstResult;
		        m_rndResult[i] = m_lstResult = m_wrkBuffer[((Y >> SIZE64) & MASK) >> 2] + X;
		        ++i;
		        ++j;
	        }

	        m_rslCounter = MSIZE;
        }

        private void Mix(ref int A, ref int B, ref int C, ref int D, ref int E, ref int F, ref int G, ref int H)
	    {
		    A ^= B << 11;
		    D += A;
		    B += C;
		    B ^= (int)((uint)C >> 2);
		    E += B;
		    C += D;
		    C ^= D << 8;
		    F += C;
		    D += E;
		    D ^= (int)((uint)E >> 16);
		    G += D;
		    E += F;
		    E ^= F << 10;
		    H += E;
		    F += G;
		    F ^= (int)((uint)G >> 4);
		    A += F;
		    G += H;
		    G ^= H << 8;
		    B += G;
		    H += A;
		    H ^= (int)((uint)A >> 9);
		    C += H;
		    A += B;
	    }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    m_accululator = 0;
                    m_cycCounter = 0;
                    m_lstResult = 0;
                    m_rslCounter = 0;

                    if (m_rndResult != null)
                    {
                        Array.Clear(m_rndResult, 0, m_rndResult.Length);
                        m_rndResult = null;
                    }
                    if (m_wrkBuffer != null)
                    {
                        Array.Clear(m_wrkBuffer, 0, m_wrkBuffer.Length);
                        m_wrkBuffer = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
