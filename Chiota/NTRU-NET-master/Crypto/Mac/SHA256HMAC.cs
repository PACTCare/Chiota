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
// An implementation of a keyed hash function; SHA-2 256 Hash based Message Authentication Code.
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// <h3>SHA256 Hash based Message Authentication Code Wrapper using SHA-2 256.</h3>
    /// <para>A SHA512 HMAC as outlined in the NIST document: Fips 198-1<cite>Fips 198-1</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new SHA256HMAC(), [DisposeEngine])
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
    /// <item><description>Key size should be equal to digest output size<cite>RFC 2104</cite>; 32 bytes, (256 bits).</description></item>
    /// <item><description>Block size is 64 bytes, (512 bits).</description></item>
    /// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
    /// <item><description>The <see cref="SHA256HMAC(bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>The <see cref="ComputeMac(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>RFC 2104: <see href="http://tools.ietf.org/html/rfc2104">HMAC: Keyed-Hashing for Message Authentication</see>.</description></item>
    /// <item><description>NIST Fips 198-1: <see href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">The Keyed-Hash Message Authentication Code (HMAC)</see>.</description></item>
    /// <item><description>NIST Fips 180-4: <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Secure Hash Standard (SHS)</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SHA256HMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "SHA256HMAC";
        private const Int32 BLOCK_SIZE = 64;
        private const Int32 DIGEST_SIZE = 32;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private SHA256 _shaDigest;
        private HMAC _shaHmac;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Ciphers internal blocksize in bytes
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
        /// Initialize the class
        /// <para>When using this constructor, you must call <see cref="Initialize(KeyParams)"/> before processing.</para>
        /// </summary>
        /// 
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        public SHA256HMAC(bool DisposeEngine = true)
        {
            _shaDigest = new SHA256();
            _shaHmac = new HMAC(_shaDigest, DisposeEngine);
        }

        /// <summary>
        /// Initialize the class and working variables.
        /// <para>When this constructor is used, <see cref="Initialize(KeyParams)"/> is called automatically.</para>
        /// </summary>
        /// 
        /// <param name="Key">HMAC Key; passed to HMAC Initialize() through constructor</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if a null Key is used</exception>
        public SHA256HMAC(byte[] Key, bool DisposeEngine = true)
        {
            if (Key == null)
                throw new CryptoMacException("SHA256HMAC:Ctor", "Key can not be null!", new ArgumentNullException());

            _shaDigest = new SHA256();
            _shaHmac = new HMAC(_shaDigest, Key, DisposeEngine);
            _isInitialized = true;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SHA256HMAC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the hash buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoMacException("SHA256HMAC:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            _shaHmac.BlockUpdate(Input, InOffset, Length);
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Mac value</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            return _shaHmac.ComputeMac(Input);
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
                throw new CryptoMacException("SHA256HMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            return _shaHmac.DoFinal(Output, OutOffset);
        }

        /// <summary>
        /// Initialize the HMAC
        /// </summary>
        /// 
        /// <param name="KeyParam">KeyParams containing HMAC Key. 
        /// <para>Uses the Key field of the <see cref="KeyParams"/> class. 
        /// Key should be equal in size to the <see cref="DigestSize"/></para>
        /// </param>
        public void Initialize(KeyParams KeyParam)
        {
            _shaHmac.Initialize(KeyParam);
            _isInitialized = true;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _shaHmac.Reset();
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _shaHmac.Update(Input);
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
            // note: digest is disposed of by hmac
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_shaHmac != null)
                    {
                        _shaHmac.Dispose();
                        _shaHmac = null;
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
