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
// XSPRsg:  XorShift+ pseudo random seed generator
// Written by John Underhill, June 1, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// XSPRsg: Generates seed material using an XorShift+ generator.
    /// <para>This generator is not generally considered a cryptographic quality generator. 
    /// This generator is suitable as a quality high-speed number generator, but not to be used directly for tasks that require secrecy, ex. key generation.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of getting a seed value:</description>
    /// <code>
    /// using (XSPRsg gen = new XSPRsg(Seed))
    ///     gen.GetSeed(Output);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng"/>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Further scramblings of Marsaglia’s <a href="http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf">Xorshift Generators</a>.</description></item>
    /// <item><description><a href="http://xorshift.di.unimi.it/">Xorshift+ generators</a> and the PRNG shootout.</description></item>
    /// </list>
    /// </remarks>
    public sealed class XSPRsg : ISeed
    {
        #region Constants
        private const string ALG_NAME = "XSPRsg";
        private const int SIZE32 = 4;
        private const int SIZE64 = 8;
        private const int SEED128 = 2;
        private const int SEED1024 = 16;
        private const ulong Z1 = 0x9E3779B97F4A7C15;
        private const ulong Z2 = 0xBF58476D1CE4E5B9;
        private const ulong Z3 = 0x94D049BB133111EB;
        private const ulong Z4 = 1181783497276652981;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private bool _isShift1024 = false;
        private uint _stateOffset = 0;
        private ulong[] m_stateSeed;
        private ulong[] m_wrkBuffer;
        private static readonly ulong[] JMP128 = new ulong[] { 0x8a5cd789635d2dffUL, 0x121fd2155c472f96UL };
        private static readonly ulong[] JMP1024 = new ulong[] {
            0x84242f96eca9c41dUL, 0xa3c65b8776f96855UL, 0x5b34a39f070b5837UL, 0x4489affce4f31a1eUL,
            0x2ffeeb0a48316f40UL, 0xdc2d9891fe68c022UL, 0x3659132bb12fea70UL, 0xaac17d8efa43cab8UL,
            0xc4cb815590989b13UL, 0x5ee975283d71c93bUL, 0x691548c86c1bd540UL, 0x7910c41d10a1e6a5UL,
            0x0b5fc64563b3e2a8UL, 0x047f7684e9fc949dUL, 0xb99181f2d8f685caUL, 0x284600e3f30e38c3UL
                };
        #endregion

        #region Properties
        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public SeedGenerators Enumeral
        {
            get { return SeedGenerators.XSPRsg; }
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
        /// <para>Seeds the 1024 generator with 128 bytes from the pool.</para>
        /// </summary>
        public XSPRsg()
        {
            byte[] rnd = new byte[SEED1024 * 8];
            m_stateSeed = new ulong[SEED1024];
            m_wrkBuffer = new ulong[SEED1024];
            new EntropyPool().GetBytes(rnd);
            Buffer.BlockCopy(rnd, 0, m_stateSeed, 0, rnd.Length);
            _isShift1024 = true;
            Reset();
        }

        /// <summary>
        /// Initialize this class using a seed value.
        /// <para>Initializing with 2 ulongs invokes the 128 bit function, initializing with 16 ulongs
        /// invokes the 1024 bit function.</para>
        /// </summary>
        ///
        /// <param name="Seed">The initial state values; can be either 2, or 16, (non-zero) 64bit values</param>
        ///
        /// <exception cref="CryptoRandomException">Thrown if an invalid seed array is used</exception>
        [CLSCompliant(false)]
        public XSPRsg(ulong[] Seed)
        {
            if (Seed.Length != SEED128 && Seed.Length != SEED1024)
                throw new CryptoRandomException("XSPRsg:CTor", "The seed array length must be either 2 or 16 long values!");

            for (int i = 0; i < Seed.Length; ++i)
            {
                if (Seed[i] == 0)
                    throw new CryptoRandomException("XSPRsg:CTor", "Seed values can not be zero!");
            }

            m_stateSeed = new ulong[Seed.Length];
            m_wrkBuffer = new ulong[Seed.Length];
            Array.Copy(Seed, m_stateSeed, Seed.Length);
            _isShift1024 = (Seed.Length == SEED1024);
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~XSPRsg()
        {
            Dispose(false);
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
            Generate(Output, Output.Length);
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
        /// Increment the state by 64 blocks; used with the 128 and 1024 implementations
        /// </summary>
        public void Jump()
        {
	        if (_isShift1024)
		        Jump1024();
	        else
		        Jump128();
        }

        /// <summary>
        /// Reinitialize the internal state
        /// </summary>
        public void Reset()
        {
            Array.Copy(m_stateSeed, 0, m_wrkBuffer, 0, m_stateSeed.Length);
        }

        /// <summary>
        /// Implementation of java's Splittable function
        /// </summary>
        /// 
        /// <param name="X">Input integer</param>
        /// 
        /// <returns>A processed long integer</returns>
        [CLSCompliant(false)]
        public ulong Split(ulong X)
        {
            ulong Z = (X += Z1);
            Z = (Z ^ (Z >> 30)) * Z2;
            Z = (Z ^ (Z >> 27)) * Z3;

            return Z ^ (Z >> 31);
        }
        #endregion

        #region Private Methods
        private void Generate(byte[] Output, int Size)
        {
	        int offset = 0;
	        ulong X;
            int len = SIZE64;

	        while (offset < Size)
	        {
		        if (_isShift1024)
			        X = Shift1024();
		        else
			        X = Shift128();

		        if (Size - offset < len)
			        len = Size - offset;

                Buffer.BlockCopy(IntUtils.ULongToBytes(X), 0, Output, offset, len);
		        offset += len;
	        }
        }

        private int Next()
        {
	        ulong X;

	        if (_isShift1024)
		        X = Shift1024();
	        else
		        X = Shift128();

            return (int)X;
        }

        private void Jump128()
        {
	        ulong s0 = 0;
	        ulong s1 = 0;

	        for (int i = 0; i < JMP128.Length; i++)
	        {
		        for (int b = 0; b < 64; b++)
		        {
			        if ((JMP128[i] & 1UL) << b != 0)
			        {
				        s0 ^= m_wrkBuffer[0];
				        s1 ^= m_wrkBuffer[1];
			        }

			        Shift128();
		        }
	        }

	        m_wrkBuffer[0] = s0;
	        m_wrkBuffer[1] = s1;
        }

        private void Jump1024()
        {
	        ulong[] T =  new ulong[16];

	        for (int i = 0; i < JMP1024.Length; i++)
	        {
		        for (int b = 0; b < 64; b++)
		        {
			        if ((JMP1024[i] & 1UL) << b != 0)
			        {
				        for (int j = 0; j < 16; j++)
					        T[j] ^= m_wrkBuffer[(j + _stateOffset) & 15];
			        }

			        Shift1024();
		        }
	        }

            Buffer.BlockCopy(T, 0, m_wrkBuffer, 0, T.Length);
        }

        private ulong Shift128()
        {
	        ulong X = m_wrkBuffer[0];
	        ulong Y = m_wrkBuffer[1];

	        m_wrkBuffer[0] = Y;
	        X ^= X << 23; // a
	        m_wrkBuffer[1] = X ^ Y ^ (X >> 18) ^ (Y >> 5); // b, c

	        return m_wrkBuffer[1] + Y; // +
        }


        private ulong Shift1024()
        {
	        ulong X = m_wrkBuffer[_stateOffset];
	        ulong Y = m_wrkBuffer[_stateOffset = (_stateOffset + 1) & 15];

	        Y ^= Y << 31; // a
	        m_wrkBuffer[_stateOffset] = Y ^ X ^ (Y >> 11) ^ (X >> 30); // b,c

            return m_wrkBuffer[_stateOffset] * Z4;
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
                    _stateOffset = 0;

                    if (m_stateSeed != null)
                    {
                        Array.Clear(m_stateSeed, 0, m_stateSeed.Length);
                        m_stateSeed = null;
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
