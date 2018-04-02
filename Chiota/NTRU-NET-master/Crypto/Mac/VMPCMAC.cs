#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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
    /// <h3>An implementation of a Variably Modified Permutation Composition based Message Authentication Code: VMPC-MAC.</h3>
    /// <para>A VMPC-MAC as outlined in the VMPC-MAC Specification<cite>VMPC-MAC</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new VMPCMAC(new RDX()))
    /// {
    ///     // initialize
    ///     mac.Initialize(KeyParams);
    ///     // get mac
    ///     Output = mac.ComputeMac(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>No fixed block size is used.</description></item>
    /// <item><description>MAC return size is 20 bytes.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>VMPC-MAC Specification: <see href="http://www.vmpcfunction.com/vmpc_mac.pdf">VMPC-MAC: A Stream Cipher Based Authenticated Encryption Scheme</see>.</description></item>
    /// <item><description>VMPC Paper: <see href="http://www.vmpcfunction.com/vmpcmac.htm>VMPC-MAC">VMPC-MAC Authenticated Encryption Scheme</see>.</description></item>
    /// <item><description>IETF: <see href="http://www.okna.wroc.pl/vmpc.pdf">VMPC One-Way Function and Stream Cipher</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class VMPCMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "VMPCMAC";
        private const int BLOCK_SIZE = 0;
        private const int DIGEST_SIZE = 20;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private bool _isInitialized = false;
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
        /// Get: The Digests internal blocksize in bytes.
        /// <para>Not used in VMPCMAC: Block size is variable.</para>
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// Get: Mac is ready to digest data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
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
        public VMPCMAC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~VMPCMAC()
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
                throw new CryptoMacException("VMPCMAC:Ctor", "The Input buffer is too short!", new ArgumentOutOfRangeException());

			for (int i = 0; i < Length; i++)
				Update(Input[i]);
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
            byte[] hash = new byte[DigestSize];

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
            if (Output.Length - OutOffset < DIGEST_SIZE)
                throw new CryptoMacException("VMPCMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            // Execute the Post-Processing Phase
			for (int r = 1; r < 25; r++)
			{
				_S = _P[(_S + _P[_N & 0xff]) & 0xff];

				_X4 = _P[(_X4 + _X3 + r) & 0xff];
				_X3 = _P[(_X3 + _X2 + r) & 0xff];
				_X2 = _P[(_X2 + _X1 + r) & 0xff];
				_X1 = _P[(_X1 + _S + r) & 0xff];
				_T[_G & 0x1f] = (byte)(_T[_G & 0x1f] ^ _X1);
				_T[(_G + 1) & 0x1f] = (byte)(_T[(_G + 1) & 0x1f] ^ _X2);
				_T[(_G + 2) & 0x1f] = (byte)(_T[(_G + 2) & 0x1f] ^ _X3);
				_T[(_G + 3) & 0x1f] = (byte)(_T[(_G + 3) & 0x1f] ^ _X4);
				_G = (byte)((_G + 4) & 0x1f);

				byte temp = _P[_N & 0xff];
				_P[_N & 0xff] = _P[_S & 0xff];
				_P[_S & 0xff] = temp;
				_N = (byte)((_N + 1) & 0xff);
			}

			// Input T to the IV-phase of the VMPC KSA
			for (int m = 0; m < 768; m++)
			{
				_S = _P[(_S + _P[m & 0xff] + _T[m & 0x1f]) & 0xff];
				byte temp = _P[m & 0xff];
				_P[m & 0xff] = _P[_S & 0xff];
				_P[_S & 0xff] = temp;
			}

			// Store 20 new outputs of the VMPC Stream Cipher input table M
			byte[] M = new byte[20];
			for (int i = 0; i < 20; i++)
			{
				_S = _P[(_S + _P[i & 0xff]) & 0xff];
				M[i] = _P[(_P[(_P[_S & 0xff]) & 0xff] + 1) & 0xff];

				byte temp = _P[i & 0xff];

				_P[i & 0xff] = _P[_S & 0xff];
				_P[_S & 0xff] = temp;
			}

			Buffer.BlockCopy(M, 0, Output, OutOffset, M.Length);

            Reset();

			return M.Length;
        }

        /// <summary>
        /// Initialize the MAC
        /// </summary>
        /// 
        /// <param name="KeyParam">VMPCMAC Key and IV.
        /// <para>Uses the Key and IV fields of the <see cref="KeyParams"/> class.
        /// Key and IV must be between 1 and 768 bytes in length.
        /// Key and IV should be equal in size.</para>
        /// </param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null or invalid Key, or IV is used</exception>
        public void Initialize(KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoMacException("VMPCMAC:Initialize", "VMPCMAC Initialize KeyParams must include a Key!", new ArgumentNullException());
            if (KeyParam.IV == null)
                throw new CryptoMacException("VMPCMAC:Initialize", "VMPCMAC Initialize KeyParams must include an IV!", new ArgumentNullException());

			_workingIV = KeyParam.IV;

			if (_workingIV == null || _workingIV.Length < 1 || _workingIV.Length > 768)
                throw new CryptoMacException("VMPCMAC:Initialize", "VMPCMAC requires 1 to 768 bytes of IV!", new ArgumentOutOfRangeException());

			_workingKey = KeyParam.Key;

			Reset();

            _isInitialized = true;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            InitKey(_workingKey, _workingIV);

			_G = _X1 = _X2 = _X3 = _X4 = _N = 0;
			_T = new byte[32];

			for (int i = 0; i < 32; i++)
				_T[i] = 0;
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _S = _P[(_S + _P[_N & 0xff]) & 0xff];
			byte C = (byte)(Input ^ _P[(_P[(_P[_S & 0xff]) & 0xff] + 1) & 0xff]);

			_X4 = _P[(_X4 + _X3) & 0xff];
			_X3 = _P[(_X3 + _X2) & 0xff];
			_X2 = _P[(_X2 + _X1) & 0xff];
			_X1 = _P[(_X1 + _S + C) & 0xff];

			_T[_G & 0x1f] = (byte)(_T[_G & 0x1f] ^ _X1);
			_T[(_G + 1) & 0x1f] = (byte)(_T[(_G + 1) & 0x1f] ^ _X2);
			_T[(_G + 2) & 0x1f] = (byte)(_T[(_G + 2) & 0x1f] ^ _X3);
			_T[(_G + 3) & 0x1f] = (byte)(_T[(_G + 3) & 0x1f] ^ _X4);

			_G = (byte) ((_G + 4) & 0x1f);

			byte temp = _P[_N & 0xff];
			_P[_N & 0xff] = _P[_S & 0xff];
			_P[_S & 0xff] = temp;
			_N = (byte)((_N + 1) & 0xff);
        }
        #endregion

        #region Private Methods
        /// <remarks>
        /// Section 3.2, table 2 <see href="http://vmpcfunction.com/vmpc_mac.pdf">VMPC-MAC: 
        /// A Stream Cipher Based Authenticated Encryption Scheme</see>
        /// </remarks>
		private void InitKey(byte[] KeyBytes, byte[] IvBytes)
		{
			_S = 0;
			_P = new byte[256];

			for (int i = 0; i < 256; i++)
				_P[i] = (byte) i;

			for (int m = 0; m < 768; m++)
			{
				_S = _P[(_S + _P[m & 0xff] + KeyBytes[m % KeyBytes.Length]) & 0xff];
				byte temp = _P[m & 0xff];
				_P[m & 0xff] = _P[_S & 0xff];
				_P[_S & 0xff] = temp;
			}

			for (int m = 0; m < 768; m++)
			{
				_S = _P[(_S + _P[m & 0xff] + IvBytes[m % IvBytes.Length]) & 0xff];
				byte temp = _P[m & 0xff];
				_P[m & 0xff] = _P[_S & 0xff];
				_P[_S & 0xff] = temp;
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
            if (!_isDisposed && Disposing)
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
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
