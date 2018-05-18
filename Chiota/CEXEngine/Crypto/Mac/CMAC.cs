#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// CMAC: An implementation of a Cipher based Message Authentication Code
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new CMAC(new RHX(), [DisposeEngine]))
    /// {
    ///     // initialize
    ///     mac.Initialize(Key, Iv);
    ///     // get mac
    ///     Output = mac.ComputeMac(Input);
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
    /// <item><description>MAC return size must be a divisible of 8.</description></item>
    /// <item><description>MAC return size can be no longer than the Cipher Block size.</description></item>
    /// <item><description>Valid Cipher block sizes are 8 and 16 byte wide.</description></item>
    /// <item><description>The <see cref="CMAC(IBlockCipher, bool)">Constructors</see> DisposeEngine parameter determines if Cipher engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The CMAC Mode for Authentication.</description></item>
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-CMAC Algorithm.</description></item>
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4494">4494</a>: The AES-CMAC-96 Algorithm and Its Use with IPsec.</description></item>
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4615">4493</a>: The AES-CMAC-PRF-128 Algorithm for the Internet Key Exchange Protocol (IKE).</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class CMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "CMAC";
        private const byte CONST_128 = (byte)0x87;
        private const byte CONST_64 = (byte)0x1b;
        #endregion

        #region Fields
        private int m_blockSize = 0;
        private KeyParams m_cipherKey;
        private ICipherMode m_cipherMode;
        private bool m_disposeEngine = true;
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        private int m_macSize;
        private byte[] m_msgCode;
        private byte[] m_wrkBuffer;
        private int m_wrkOffset;
        private byte[] m_K1, m_K2;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Macs internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return m_blockSize; }
            set { m_blockSize = value; }
        }

        /// <summary>
        /// Get: The macs type name
        /// </summary>
        public Macs Enumeral
        {
            get { return Macs.CMAC; }
        }

        /// <summary>
        /// Get: Mac is ready to digest data
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
            private set { m_isInitialized = value; }
        }

        /// <summary>
        /// Get: Size of returned mac in bytes
        /// </summary>
        public int MacSize
        {
            get { return m_macSize; }
        }

        /// <summary>
        /// Get: Algorithm name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class with the block cipher enumeration name
        /// </summary>
        /// <param name="EngineType">The block cipher enumeration name</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid block size is used</exception>
        public CMAC(BlockCiphers EngineType)
        {
            IBlockCipher cipher = Helper.BlockCipherFromName.GetInstance(EngineType);
            if (cipher.BlockSize != 16 && cipher.BlockSize != 32)
                throw new CryptoMacException("CMAC:Ctor", "Block size must be 128 or 256 bits!", new ArgumentException());

            m_disposeEngine = true;
            m_cipherMode = new CBC(cipher);
            m_blockSize = m_cipherMode.BlockSize;
            m_macSize = cipher.BlockSize;
            m_msgCode = new byte[m_blockSize];
            m_wrkBuffer = new byte[m_blockSize];
            m_wrkOffset = 0;
        }

        /// <summary>
        /// Initialize this class with a block cipher instance
        /// </summary>
        /// <param name="Cipher">Instance of the block cipher</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid block size is used</exception>
        public CMAC(IBlockCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher.BlockSize != 16 && Cipher.BlockSize != 32)
                throw new CryptoMacException("CMAC:Ctor", "Block size must be 128 or 256 bits!", new ArgumentException());

            m_disposeEngine = DisposeEngine;
            m_cipherMode = new CBC(Cipher);
            m_blockSize = m_cipherMode.BlockSize;
            m_macSize = Cipher.BlockSize;
            m_msgCode = new byte[m_blockSize];
            m_wrkBuffer = new byte[m_blockSize];
            m_wrkOffset = 0;
        }

        private CMAC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CMAC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoMacException("CMAC:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            if (m_wrkOffset == m_blockSize)
            {
                m_cipherMode.Transform(m_wrkBuffer, 0, m_msgCode, 0);
                m_wrkOffset = 0;
            }

            int diff = m_blockSize - m_wrkOffset;
            if (Length > diff)
            {
                Buffer.BlockCopy(Input, InOffset, m_wrkBuffer, m_wrkOffset, diff);
                m_cipherMode.Transform(m_wrkBuffer, 0, m_msgCode, 0);
                m_wrkOffset = 0;
                Length -= diff;
                InOffset += diff;

                while (Length > m_blockSize)
                {
                    m_cipherMode.Transform(Input, InOffset, m_msgCode, 0);
                    Length -= m_blockSize;
                    InOffset += m_blockSize;
                }
            }

            if (Length > 0)
            {
                Buffer.BlockCopy(Input, InOffset, m_wrkBuffer, m_wrkOffset, Length);
                m_wrkOffset += Length;
            }
        }

        /// <summary>
        /// Get the Mac hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Mac Hash value</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            if (!m_isInitialized)
                throw new CryptoGeneratorException("CMAC:ComputeMac", "The Mac is not initialized!", new InvalidOperationException());

            byte[] hash = new byte[m_macSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Process the last block of data
        /// </summary>
        /// 
        /// <param name="Output">The hash value return</param>
        /// <param name="OutOffset">The offset in the data</param>
        /// 
        /// <returns>The number of bytes processed</returns>
        /// 
        /// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < m_macSize)
                throw new CryptoMacException("CMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            if (m_wrkOffset != m_blockSize)
	        {
		        ISO7816 pad =  new ISO7816();
		        pad.AddPadding(m_wrkBuffer, m_wrkOffset);
                for (int i = 0; i < m_msgCode.Length; i++)
                    m_wrkBuffer[i] ^= m_K2[i];
	        }
	        else
	        {
                for (int i = 0; i < m_msgCode.Length; i++)
                    m_wrkBuffer[i] ^= m_K1[i];
	        }

	        m_cipherMode.Transform(m_wrkBuffer, 0, m_msgCode, 0);
            Buffer.BlockCopy(m_msgCode, 0, Output, OutOffset, m_macSize);
	        Reset();

            return m_macSize;
        }

        /// <summary>
        /// Initialize the Cipher MAC.
        /// <para>Uses the Key or IKM field, and optionally the IV field of the KeyParams class.</para>
        /// </summary>
        /// 
        /// <param name="MacKey">A byte array containing the cipher Key. 
        /// <para>Key size must be one of the <c>LegalKeySizes</c> of the underlying cipher.</para>
        /// </param>
        /// <param name="IV">A byte array containing the cipher Initialization Vector.
        /// <para>IV size must be the ciphers blocksize.</para></param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void Initialize(byte[] MacKey, byte[] IV)
        {
            if (MacKey == null)
                throw new CryptoMacException("CMAC:Initialize", "Key can not be null!", new ArgumentNullException());

            if (IV == null)
                IV = new byte[m_blockSize];
            if (IV.Length != m_blockSize)
                Array.Resize<byte>(ref IV, m_blockSize);

            m_cipherKey =  new KeyParams(MacKey, IV);
	        m_cipherMode.Initialize(true, m_cipherKey);
            byte[] lu = new byte[m_blockSize];
	        byte[] tmpz = new byte[m_blockSize];
	        m_cipherMode.Transform(tmpz, 0, lu, 0);
	        m_K1 = GenerateSubkey(lu);
	        m_K2 = GenerateSubkey(m_K1);
	        m_cipherMode.Initialize(true, m_cipherKey);
	        m_isInitialized = true;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            m_cipherMode.Initialize(true, m_cipherKey);
            Array.Clear(m_wrkBuffer, 0, m_wrkBuffer.Length);
            m_wrkOffset = 0;
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            if (m_wrkOffset == m_wrkBuffer.Length)
            {
                m_cipherMode.Transform(m_wrkBuffer, 0, m_msgCode, 0);
                m_wrkOffset = 0;
            }

            m_wrkBuffer[m_wrkOffset++] = Input;
        }
        #endregion

        #region Private Methods
        private byte[] GenerateSubkey(byte[] Input)
        {
            int firstBit = (Input[0] & 0xFF) >> 7;
            byte[] ret = new byte[Input.Length];

            for (int i = 0; i < Input.Length - 1; i++)
                ret[i] = (byte)((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));
            
            ret[Input.Length - 1] = (byte)(Input[Input.Length - 1] << 1);

            if (firstBit == 1)
                ret[Input.Length - 1] ^= Input.Length == m_blockSize ? CONST_128 : CONST_64;
            
            return ret;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (m_cipherMode != null && m_disposeEngine)
                    {
                        m_cipherMode.Dispose();
                        m_cipherMode = null;
                    }
                    if (m_msgCode != null)
                    {
                        Array.Clear(m_msgCode, 0, m_msgCode.Length);
                        m_msgCode = null;
                    }
                    if (m_wrkBuffer != null)
                    {
                        Array.Clear(m_wrkBuffer, 0, m_wrkBuffer.Length);
                        m_wrkBuffer = null;
                    }
                    if (m_K1 != null)
                    {
                        Array.Clear(m_K1, 0, m_K1.Length);
                        m_K1 = null;
                    }
                    if (m_K2 != null)
                    {
                        Array.Clear(m_K2, 0, m_K2.Length);
                        m_K2 = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
