#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
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
// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// <h3>An implementation of a Hash based Message Authentication Code: HMAC<cite>Fips 198-1</cite>.</h3>
    /// <para>A HMAC as outlined in the NIST document: Fips 198-1<cite>Fips 198-1</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new HMAC(new SHA256Digest(), [DisposeEngine]))
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
    /// <revision date="2014/11/11" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Changes to formatting and documentation</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest">VTDev.Libraries.CEXEngine.Crypto.Digest Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Key size should be equal to digest output size<cite>RFC 2104</cite>.</description></item>
    /// <item><description>Block size is the Digests engines block size.</description></item>
    /// <item><description>Digest size is the Digest engines digest return size.</description></item>
    /// <item><description>The <see cref="HMAC(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>The <see cref="ComputeMac(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>RFC 2104: <see href="http://tools.ietf.org/html/rfc2104">HMAC: Keyed-Hashing for Message Authentication</see>.</description></item>
    /// <item><description>Fips 198-1: <see href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">The Keyed-Hash Message Authentication Code (HMAC)</see>.</description></item>
    /// <item><description>Fips 180-4: <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Secure Hash Standard (SHS)</see>.</description></item>
    /// <item><description>NMAC and HMAC Security: <see href="http://cseweb.ucsd.edu/~mihir/papers/hmac-new.pdf">NMAC and HMAC Security Proofs</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class HMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "HMAC";
        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;
        #endregion

        #region Fields
        private int _blockSize;
        private int _digestSize;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private byte[] _inputPad;
        private bool _isInitialized = false;
        private IDigest _msgDigest;
        private byte[] _outputPad;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _msgDigest.BlockSize; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _msgDigest.DigestSize; }
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
        /// 
        /// <param name="Digest">Message Digest instance</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null digest is used</exception>
        public HMAC(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoMacException("HMAC:Ctor", "Digest can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _msgDigest = Digest;
            _digestSize = Digest.DigestSize;
            _blockSize = Digest.BlockSize;
            _inputPad = new byte[_blockSize];
            _outputPad = new byte[_blockSize];
        }

        /// <summary>
        /// Initialize the class and working variables.
        /// <para>When this constructor is used, <see cref="Initialize(KeyParams)"/> is called automatically.</para>
        /// </summary>
        /// 
        /// <param name="Digest">Message Digest instance</param>
        /// <param name="Key">HMAC Key; passed to HMAC Initialize() through constructor</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null digest is used</exception>
        public HMAC(IDigest Digest, byte[] Key, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoMacException("HMAC:Ctor", "Digest can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _msgDigest = Digest;
            _digestSize = Digest.DigestSize;
            _blockSize = Digest.BlockSize;
            _inputPad = new byte[_blockSize];
            _outputPad = new byte[_blockSize];

            KeyParams keyParam = new KeyParams(Key);
            Initialize(keyParam);
            keyParam.Dispose();
        }

        private HMAC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~HMAC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the digest
        /// </summary>
        /// 
        /// <param name="Input">Hash input data</param>
        /// <param name="InOffset">Starting position with the Input array</param>
        /// <param name="Length">Length of data to process</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if (InOffset + Length > Input.Length)
                throw new CryptoMacException("HMAC:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            _msgDigest.BlockUpdate(Input, InOffset, Length);
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>HMAC hash value</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            byte[] hash = new byte[_msgDigest.DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Completes processing and returns the HMAC code
        /// </summary>
        /// 
        /// <param name="Output">Output array that receives the hash code</param>
        /// <param name="OutOffset">Offset within Output array</param>
        /// 
        /// <returns>The number of bytes processed</returns>
        /// 
        /// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < _msgDigest.DigestSize)
                throw new CryptoMacException("HMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            byte[] temp = new byte[_digestSize];
            _msgDigest.DoFinal(temp, 0);

            _msgDigest.BlockUpdate(_outputPad, 0, _outputPad.Length);
            _msgDigest.BlockUpdate(temp, 0, temp.Length);

            int msgLen = _msgDigest.DoFinal(Output, OutOffset);

            // reinitialise the digest
            _msgDigest.BlockUpdate(_inputPad, 0, _inputPad.Length);

            Reset();

            return msgLen;
        }

        /// <summary>
        /// Initialize the HMAC
        /// </summary>
        /// 
        /// <param name="KeyParam">HMAC Key. 
        /// <para>Uses the Key field of the <see cref="KeyParams"/> class, <c>Key</c> parameter.
        /// Key should be equal in size to the <see cref="DigestSize"/></para>
        /// </param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if the Key is null or less than digest size</exception>
        public void Initialize(KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoMacException("HMAC:Initialize", "Key can not be null!", new ArgumentNullException());

            _msgDigest.Reset();
            int keyLength = KeyParam.Key.Length;

            // compress to digest size
            if (KeyParam.Key.Length > _blockSize)
            {
                _msgDigest.BlockUpdate(KeyParam.Key, 0, KeyParam.Key.Length);
                _msgDigest.DoFinal(_inputPad, 0);
                keyLength = _digestSize;
            }
            else
            {
                Array.Copy(KeyParam.Key, 0, _inputPad, 0, keyLength);
            }

            Array.Clear(_inputPad, keyLength, _blockSize - keyLength);
            Array.Copy(_inputPad, 0, _outputPad, 0, _blockSize);

            XOR(_inputPad, IPAD);
            XOR(_outputPad, OPAD);

            // initialise the digest
            _msgDigest.BlockUpdate(_inputPad, 0, _inputPad.Length);
            _isInitialized = true;
        }

        /// <summary>
        /// Reset and initialize the underlying digest
        /// </summary>
        public void Reset()
        {
            _msgDigest.Reset();
            _msgDigest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        /// <summary>
        /// Update the digest with 1 byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _msgDigest.Update(Input);
        }

        #endregion

        #region Private Methods
        private static void XOR(byte[] A, byte N)
        {
            for (int i = 0; i < A.Length; ++i)
                A[i] ^= N;
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
                    if (_msgDigest != null && _disposeEngine)
                    {
                        _msgDigest.Dispose();
                        _msgDigest = null;
                    }
                    if (_inputPad != null)
                    {
                        Array.Clear(_inputPad, 0, _inputPad.Length);
                        _inputPad = null;
                    }
                    if (_outputPad != null)
                    {
                        Array.Clear(_outputPad, 0, _outputPad.Length);
                        _outputPad = null;
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
