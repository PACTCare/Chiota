#region Directives
using System;
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
// An implementation of a Variably Modified Permutation Composition based Message Authentication Code (VMPC-MAC).
// Written by John Underhill, January 11, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// VMAC: An implementation of a Variably Modified Permutation Composition based Message Authentication Code
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new VMAC())
    /// {
    ///     // initialize
    ///     mac.Initialize(Key, Iv);
    ///     // get mac
    ///     Output = mac.ComputeMac(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>No fixed block size is used.</description></item>
    /// <item><description>MAC return size is 20 bytes.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>VMPC <a href="http://www.vmpcfunction.com/vmpc_mac.pdf">MAC Specification</a>:  VMPC-MAC: A Stream Cipher Based Authenticated Encryption Scheme.</description></item>
    /// <item><description>VMPC <a href="http://www.vmpcfunction.com/vmpcmac.htm">VMPC-MAC</a> Authenticated Encryption Scheme.</description></item>
    /// <item><description>IETF <a href="http://www.okna.wroc.pl/vmpc.pdf">VMPC One-Way Function</a> and Stream Cipher.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class VMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "VMAC";
        private const int BLOCK_SIZE = 256;
        private const int DIGEST_SIZE = 20;
	    private const byte CT1F = (byte)0x1F;
        private const byte CTFF = (byte)0xFF;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        private byte _G;
        private byte _N = 0;
        private byte[] _P = null;
        private byte _S = 0;
        private byte[] _T;
        private byte _X1, _X2, _X3, _X4;
        private byte[] _workingKey;
        private byte[] _workingIV;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Macs internal blocksize in bytes.
        /// <para>Not used in VMAC: Block size is variable.</para>
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public Macs Enumeral
        {
            get { return Macs.VMAC; }
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
            get { return DIGEST_SIZE; }
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
        /// Initialize this class
        /// </summary>
        public VMAC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~VMAC()
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
            if (!m_isInitialized)
                throw new CryptoGeneratorException("VMAC:BlockUpdate", "The Mac is not initialized!", new InvalidOperationException());
            if ((InOffset + Length) > Input.Length)
                throw new CryptoMacException("VMAC:Ctor", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            for (int i = 0; i < Length; ++i)
                Update(Input[InOffset + i]);
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
                throw new CryptoGeneratorException("VMAC:ComputeMac", "The Mac is not initialized!", new InvalidOperationException());

            byte[] hash = new byte[MacSize];

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
            if (!m_isInitialized)
                throw new CryptoGeneratorException("VMAC:DoFinal", "The Mac is not initialized!", new InvalidOperationException());
            if (Output.Length - OutOffset < DIGEST_SIZE)
                throw new CryptoMacException("VMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

	        int ctr = 1;
	        byte ptmp;

	        // execute the post-processing phase
	        while (ctr != 25)
	        {
		        _S = _P[(_S + _P[_N & CTFF]) & CTFF];
		        _X4 = _P[(_X4 + _X3 + ctr) & CTFF];
		        _X3 = _P[(_X3 + _X2 + ctr) & CTFF];
		        _X2 = _P[(_X2 + _X1 + ctr) & CTFF];
		        _X1 = _P[(_X1 + _S + ctr) & CTFF];
		        _T[_G & CT1F] = (byte)(_T[_G & CT1F] ^ _X1);
		        _T[(_G + 1) & CT1F] = (byte)(_T[(_G + 1) & CT1F] ^ _X2);
		        _T[(_G + 2) & CT1F] = (byte)(_T[(_G + 2) & CT1F] ^ _X3);
		        _T[(_G + 3) & CT1F] = (byte)(_T[(_G + 3) & CT1F] ^ _X4);
		        _G = (byte)((_G + 4) & CT1F);

		        ptmp = _P[_N & CTFF];
		        _P[_N & CTFF] = _P[_S & CTFF];
		        _P[_S & CTFF] = ptmp;
		        _N = (byte)((_N + 1) & CTFF);

		        ++ctr;
	        }

	        // input T to the IV-phase of the VMPC KSA
	        ctr = 0;
	        while (ctr != 768)
	        {
		        _S = _P[(_S + _P[ctr & CTFF] + _T[ctr & CT1F]) & CTFF];
		        ptmp = _P[ctr & CTFF];
		        _P[ctr & CTFF] = _P[_S & CTFF];
		        _P[_S & CTFF] = ptmp;

		        ++ctr;
	        }

	        // store 20 new outputs of the VMPC Stream Cipher input table M
	        byte[] M =  new byte[20];
	        ctr = 0;
	        while (ctr != 20)
	        {
		        _S = _P[(_S + _P[ctr & CTFF]) & CTFF];
		        M[ctr] = _P[(_P[(_P[_S & CTFF]) & CTFF] + 1) & CTFF];
		        ptmp = _P[ctr & CTFF];
		        _P[ctr & CTFF] = _P[_S & CTFF];
		        _P[_S & CTFF] = ptmp;

		        ++ctr;
	        }

			Buffer.BlockCopy(M, 0, Output, OutOffset, M.Length);
            Reset();

			return M.Length;
        }

        /// <summary>
        /// Initialize the VMPC MAC.
        /// <para>Uses the Key and IV fields of the KeyParams class.</para>
        /// </summary>
        /// 
        /// <param name="MacKey">A byte array containing the Key</param>
        /// <param name="IV">A byte array containing the Initialization Vector</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null or invalid Key, or IV is used</exception>
        public void Initialize(byte[] MacKey, byte[] IV)
        {
            if (MacKey == null || MacKey.Length < 1)
                throw new CryptoMacException("VMAC:Initialize", "Key can not be zero length or null!", new ArgumentNullException());
            if (IV == null)
                throw new CryptoMacException("VMAC:Initialize", "The IV can not be null!", new ArgumentNullException());
            if (IV.Length < 1 || IV.Length > 768)
                throw new CryptoMacException("VMAC:Initialize", "VMAC requires 1 to 768 bytes of IV!", new ArgumentOutOfRangeException());

			_workingIV = (byte[])IV.Clone();
            _workingKey = (byte[])MacKey.Clone();
			Reset();

            m_isInitialized = true;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _G = _N = _S = _X1 = _X2 = _X3 = _X4 = 0;
            _P = new byte[256];
			_T = new byte[32];
			for (int i = 0; i < 32; i++)
				_T[i] = 0;

            InitKey(_workingKey, _workingIV);
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _S = _P[(_S + _P[_N & CTFF]) & CTFF];
            byte btmp = (byte)(Input ^ _P[(_P[(_P[_S & CTFF]) & CTFF] + 1) & CTFF]);

            _X4 = _P[(_X4 + _X3) & CTFF];
            _X3 = _P[(_X3 + _X2) & CTFF];
            _X2 = _P[(_X2 + _X1) & CTFF];
            _X1 = _P[(_X1 + _S + btmp) & CTFF];
            _T[_G & CT1F] = (byte)(_T[_G & CT1F] ^ _X1);
            _T[(_G + 1) & CT1F] = (byte)(_T[(_G + 1) & CT1F] ^ _X2);
            _T[(_G + 2) & CT1F] = (byte)(_T[(_G + 2) & CT1F] ^ _X3);
            _T[(_G + 3) & CT1F] = (byte)(_T[(_G + 3) & CT1F] ^ _X4);
            _G = (byte)((_G + 4) & CT1F);

            btmp = _P[_N & CTFF];
            _P[_N & CTFF] = _P[_S & CTFF];
            _P[_S & CTFF] = btmp;
            _N = (byte)((_N + 1) & CTFF);
        }
        #endregion

        #region Private Methods
        /// <remarks>
        /// Section 3.2, table 2 <a href="http://vmpcfunction.com/vmpc_mac.pdf">VMPC-MAC</a>: 
        /// A Stream Cipher Based Authenticated Encryption Scheme
        /// </remarks>
		private void InitKey(byte[] Key, byte[] Iv)
		{
            int ctr = 0;

            while (ctr != 256)
            {
                _P[ctr] = (byte)ctr;
                ++ctr;
            }

            byte btmp = 0;

            ctr = 0;
            while (ctr != 768)
            {
                _S = _P[(_S + _P[ctr & CTFF] + Key[ctr % Key.Length]) & CTFF];
                btmp = _P[ctr & CTFF];
                _P[ctr & CTFF] = _P[_S & CTFF];
                _P[_S & CTFF] = btmp;
                ++ctr;
            }

            ctr = 0;
            while (ctr != 768)
            {
                _S = _P[(_S + _P[ctr & CTFF] + Iv[ctr % Iv.Length]) & CTFF];
                btmp = _P[ctr & CTFF];
                _P[ctr & CTFF] = _P[_S & CTFF];
                _P[_S & CTFF] = btmp;
                ++ctr;
            }

            _N = 0;
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
                    if (_P != null)
                    {
                        Array.Clear(_P, 0, _P.Length);
                        _P = null;
                    }
                    if (_T != null)
                    {
                        Array.Clear(_T, 0, _T.Length);
                        _T = null;
                    }
                    if (_N != 0)
                        _N = 0;
                    if (_S != 0)
                        _S = 0;
                    if (_X1 != 0)
                        _X1 = 0;
                    if (_X2 != 0)
                        _X2 = 0;
                    if (_X3 != 0)
                        _X3 = 0;
                    if (_X4 != 0)
                        _X4 = 0;
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
