#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// SP20Rsg:  Crypto Service Provider random seed generator
// Written by John Underhill, June 1, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// SP20Rsg: A parallelized Salsa20 deterministic random byte generator implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ISeed</c> interface:</description>
    /// <code>
    /// using (ISeed rnd = new SP20Drbg())
    /// {
    ///     // generate bytes
    ///     rnd.GetSeed(Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Valid Seed sizes are 24 and 40 bytes.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SP20Rsg : ISeed
    {
        #region Constants
        private const string ALG_NAME = "SP20Rsg";
        private const int SEED24 = 24;
        private const int SEED40 = 40;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private byte[] m_stateSeed;
        private SBG m_rndGenerator;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public SeedGenerators Enumeral
        {
            get { return SeedGenerators.SP20Rsg; }
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
        /// Initialize this class using the entropy pool.
        /// <para>This constructor will use the EntropyPool to seed the generator</para>
        /// </summary>
        public SP20Rsg()
        {
            m_stateSeed = new byte[SEED40];
            new EntropyPool().GetBytes(m_stateSeed);
            Reset();
        }

        /// <summary>
        /// Initialize this class using a seed value.
        /// </summary>
        ///
        /// <param name="Seed">The initial state values; must be 48 or 320 bytes</param>
        ///
        /// <exception cref="VTDev.Libraries.CEXEngine.CryptoException.CryptoRandomException">Thrown if an invalid seed size is used</exception>
        public SP20Rsg(byte[] Seed)
        {
            if (Seed.Length != SEED24 && Seed.Length != SEED40)
                throw new CryptoRandomException("SP20Rsg:Ctor", "The seed array length must be either 24 or 40 bytes exactly!");

            m_stateSeed = new byte[Seed.Length];
            Array.Copy(Seed, m_stateSeed, Seed.Length);
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SP20Rsg()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>A pseudo random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];

            m_rndGenerator.Generate(data);

            return data;
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">The destination array</param>
        public void GetBytes(byte[] Output)
        {
            m_rndGenerator.Generate(Output);
        }

        /// <summary>
        /// Reinitialize the internal state
        /// </summary>
        public void Reset()
        {
            if (m_rndGenerator != null)
            {
                m_rndGenerator.Dispose();
                m_rndGenerator = null;
            }

            m_rndGenerator = new SBG(20);
            m_rndGenerator.Initialize(m_stateSeed);
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
                    if (m_rndGenerator != null)
                    {
                        m_rndGenerator.Dispose();
                        m_rndGenerator = null;
                    }
                    if (m_stateSeed != null)
                    {
                        Array.Clear(m_stateSeed, 0, m_stateSeed.Length);
                        m_stateSeed = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
