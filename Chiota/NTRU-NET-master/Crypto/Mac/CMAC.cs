#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
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
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// <h3>An implementation of a Cipher based Message Authentication Code: CMAC.</h3>
    /// <para>A CMAC as outlined in the NIST document: SP800-38B<cite>SP800-38B</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new CMAC(new RDX(), [DisposeEngine]))
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">VTDev.Libraries.CEXEngine.Crypto.Engines Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>MAC return size must be a divisible of 8.</description></item>
    /// <item><description>MAC return size can be no longer than the Cipher Block size.</description></item>
    /// <item><description>Valid Cipher block sizes are 8 and 16 byte wide.</description></item>
    /// <item><description>The <see cref="CMAC(IBlockCipher, int, bool)">Constructors</see> DisposeEngine parameter determines if Cipher engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-38B: <see href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">The CMAC Mode for Authentication</see>.</description></item>
    /// <item><description>RFC 4493: <see href="http://tools.ietf.org/html/rfc4493">The AES-CMAC Algorithm</see>.</description></item>
    /// <item><description>RFC 4494: <see href="http://tools.ietf.org/html/rfc4494">The AES-CMAC-96 Algorithm and Its Use with IPsec</see>.</description></item>
    /// <item><description>RFC 4493: <see href="http://tools.ietf.org/html/rfc4615">The AES-CMAC-PRF-128 Algorithm for the Internet Key Exchange Protocol (IKE)</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
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
        private int _blockSize = 0;
        private ICipherMode _cipherType;
        private int _digestSize;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private byte[] _msgCode;
        private byte[] _tmpZeroes;
        private byte[] _wrkBuffer;
        private int _wrkOffset;
        private byte[] _L, _LU, _LU2;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _blockSize; }
            set { _blockSize = value; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _digestSize; }
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
        /// Initialize the class
        /// </summary>
        /// <param name="Cipher">Instance of the block cipher</param>
        /// <param name="MacBits">Expected MAC return size in Bits; must be less or equal to Cipher Block size in bits</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Mac or block size is used</exception>
        public CMAC(IBlockCipher Cipher, int MacBits, bool DisposeEngine = true)
        {
            if ((MacBits % 8) != 0)
                throw new CryptoMacException("CMAC:Ctor", "MAC size must be multiple of 8!", new ArgumentOutOfRangeException());
            if (MacBits > (Cipher.BlockSize * 8))
                throw new CryptoMacException("CMAC:Ctor", String.Format("MAC size must be less or equal to {0}!", Cipher.BlockSize * 8), new ArgumentOutOfRangeException());
            if (Cipher.BlockSize != 8 && Cipher.BlockSize != 16)
                throw new CryptoMacException("CMAC:Ctor", "Block size must be either 64 or 128 bits!", new ArgumentException());

            _disposeEngine = DisposeEngine;
            _cipherType = new CBC(Cipher);
            _blockSize = _cipherType.BlockSize;
            _digestSize = MacBits / 8;
            _msgCode = new byte[_blockSize];
            _wrkBuffer = new byte[_blockSize];
            _tmpZeroes = new byte[_blockSize];
            _wrkOffset = 0;
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

            int gapLen = _blockSize - _wrkOffset;

            if (Length > gapLen)
            {
                Buffer.BlockCopy(Input, InOffset, _wrkBuffer, _wrkOffset, gapLen);

                _cipherType.Transform(_wrkBuffer, 0, _msgCode, 0);

                _wrkOffset = 0;
                Length -= gapLen;
                InOffset += gapLen;

                while (Length > _blockSize)
                {
                    _cipherType.Transform(Input, InOffset, _msgCode, 0);

                    Length -= _blockSize;
                    InOffset += _blockSize;
                }
            }

            Buffer.BlockCopy(Input, InOffset, _wrkBuffer, _wrkOffset, Length);

            _wrkOffset += Length;
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
            byte[] hash = new byte[_digestSize];

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
            if (Output.Length - OutOffset < _digestSize)
                throw new CryptoMacException("CMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            byte[] lu;

            if (_wrkOffset == _blockSize)
            {
                lu = _LU;
            }
            else
            {
                new ISO7816().AddPadding(_wrkBuffer, _wrkOffset);
                lu = _LU2;
            }

            for (int i = 0; i < _msgCode.Length; i++)
                _wrkBuffer[i] ^= lu[i];

            _cipherType.Transform(_wrkBuffer, 0, _msgCode, 0);

            Buffer.BlockCopy(_msgCode, 0, Output, OutOffset, _digestSize);

            Reset();

            return _digestSize;
        }

        /// <summary>
        /// Initialize the MAC
        /// </summary>
        /// 
        /// <param name="KeyParam">A <see cref="KeyParams"/> containing Key and IV. 
        /// <para>Uses the Key and IV fields of the KeyParams parameter.
        /// Key size must be one of the <c>LegalKeySizes</c> of the underlying cipher.
        /// IV size must be the ciphers blocksize.
        /// </para>
        /// </param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void Initialize(KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoMacException("CMAC:Initialize", "Key can not be null!", new ArgumentNullException());

            byte[] tmpIv = new byte[_blockSize];
            // convert for cipher
            KeyParams key = new KeyParams(KeyParam.Key, tmpIv);
            _cipherType.Initialize(true, key);

            _L = new byte[_tmpZeroes.Length];
            _cipherType.Transform(_tmpZeroes, 0, _L, 0);
            _LU = DoubleLu(_L);
            _LU2 = DoubleLu(_LU);
            _cipherType.Initialize(true, key);

            _isInitialized = true;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            Array.Clear(_wrkBuffer, 0, _wrkBuffer.Length);
            _wrkOffset = 0;
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            if (_wrkOffset == _wrkBuffer.Length)
            {
                _cipherType.Transform(_wrkBuffer, 0, _msgCode, 0);
                _wrkOffset = 0;
            }

            _wrkBuffer[_wrkOffset++] = Input;
        }
        #endregion

        #region Private Methods
        private byte[] DoubleLu(byte[] Input)
        {
            int firstBit = (Input[0] & 0xFF) >> 7;
            byte[] ret = new byte[Input.Length];

            for (int i = 0; i < Input.Length - 1; i++)
                ret[i] = (byte)((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));
            
            ret[Input.Length - 1] = (byte)(Input[Input.Length - 1] << 1);

            if (firstBit == 1)
                ret[Input.Length - 1] ^= Input.Length == 16 ? CONST_128 : CONST_64;
            
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_cipherType != null && _disposeEngine)
                    {
                        _cipherType.Dispose();
                        _cipherType = null;
                    }
                    if (_msgCode != null)
                    {
                        Array.Clear(_msgCode, 0, _msgCode.Length);
                        _msgCode = null;
                    }
                    if (_tmpZeroes != null)
                    {
                        Array.Clear(_tmpZeroes, 0, _tmpZeroes.Length);
                        _tmpZeroes = null;
                    }
                    if (_wrkBuffer != null)
                    {
                        Array.Clear(_wrkBuffer, 0, _wrkBuffer.Length);
                        _wrkBuffer = null;
                    }
                    if (_L != null)
                    {
                        Array.Clear(_L, 0, _L.Length);
                        _L = null;
                    }
                    if (_LU != null)
                    {
                        Array.Clear(_LU, 0, _LU.Length);
                        _LU = null;
                    }
                    if (_LU2 != null)
                    {
                        Array.Clear(_LU2, 0, _LU2.Length);
                        _LU2 = null;
                    }
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
