#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
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
// CTRRsg:  Crypto Service Provider random seed generator
// Written by John Underhill, June 1, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// CTRRsg: An implementation of a Encryption Counter based Deterministic Random Byte Generator
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>ISeed</c> interface:</description>
    /// <code>
    /// using (ISeed rnd = new CTRRsg(Salt))
    /// {
    ///     // generate bytes
    ///     rnd.GetBytes(Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Creates psuedo random using the RHX block cipher (Rijndael) running in counter mode.</description></item>
    /// <item><description>Initializing with a 48 byte seed produces an AES256 configuration, the 320 byte seed uses extended RHX with 22 rounds.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CTRRsg : ISeed
    {
        #region Constants
        private const string ALG_NAME = "CTRRsg";
        private const int SEED48 = 48;
        private const int SEED336 = 336;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private byte[] m_stateSeed;
        private CMG m_rndGenerator;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public SeedGenerators Enumeral
        {
            get { return SeedGenerators.CTRRsg; }
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
        /// <para>This constructor will use the EntropyPool to initialize RHX with 22 rounds and a 2560 bit key</para>
        /// </summary>
        public CTRRsg()
        {
            m_stateSeed = new byte[SEED336];
            new EntropyPool().GetBytes(m_stateSeed);
            Reset();
        }

        /// <summary>
        /// Initialize this class using a seed value.
        /// <para>This constructor initialize RHX with either AES256 (48 bytes) or the extended cipher with 22 rounds (320 bytes)</para>
        /// </summary>
        ///
        /// <param name="Seed">The initial state values; must be 48 or 320 bytes</param>
        ///
        /// <exception cref="VTDev.Libraries.CEXEngine.CryptoException.CryptoRandomException">Thrown if an invalid seed size is used</exception>
        public CTRRsg(byte[] Seed)
        {
            if (Seed.Length != SEED48 && Seed.Length != SEED336)
                throw new CryptoRandomException("CTRRsg:Ctor", "The seed array length must be either 48 or 320 bytes exactly!");

            m_stateSeed = new byte[Seed.Length];
            Array.Copy(Seed, m_stateSeed, Seed.Length);
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CTRRsg()
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

            int rds = m_stateSeed.Length == 48 ? 14 : 22;
            RHX eng = new RHX(16, rds);
            m_rndGenerator = new CMG(eng);
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
