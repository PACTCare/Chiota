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
// An implementation of a Output FeedBack Mode (OFB).
// Written by John Underhill, January 2, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode
{
    /// <summary>
    /// <h3>Implements a Output FeedBack Mode: OFB.</h3>
    /// <para>OFB as outlined in the NIST document: SP800-38A<cite>SP800-38A</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new OFB(new RDX(), [DisposeEngine]))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
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
    /// <item><description>Cipher Engine is automatically disposed of unless DisposeEngine is set to <c>false</c> in the class constructor <see cref="CBC(IBlockCipher, bool)"/></description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST: <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</see>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class OFB : ICipherMode
    {
        #region Constants
        private const string ALG_NAME = "OFB";
        #endregion

        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 8;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private byte[] _ofbIv;
        private byte[] _ofbBuffer;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher
        /// </summary>
        public int BlockSize
        {
            get { return _blockSize; }
            private set { _blockSize = value; }
        }

        /// <summary>
        /// Get: Underlying Cipher
        /// </summary>
        public IBlockCipher Engine
        {
            get { return _blockCipher; }
            private set { _blockCipher = value; }
        }

        /// <summary>
        /// Get: Initialized for encryption, false for decryption
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: The current state of the initialization Vector
        /// </summary>
        public byte[] IV
        {
            get { return (byte[])_ofbIv.Clone(); }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Cipher is used</exception>
        public OFB(IBlockCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new CryptoSymmetricException("OFB:CTor", "The Cipher can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _blockCipher = Cipher;
            _blockSize = _blockCipher.BlockSize;
            _ofbIv = new byte[_blockCipher.BlockSize];
            _ofbBuffer = new byte[_blockCipher.BlockSize];
        }

        private OFB()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~OFB()
        {
            Dispose(false);
        }
        #endregion

        #region Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is used. for encryption, false to decrypt</param>
        /// <param name="KeyParam">The KeyParams containing key and vector</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null Key or IV is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("OFB:Initialize", "Key can not be null!", new ArgumentNullException());
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("OFB:Initialize", "IV can not be null!", new ArgumentNullException());

            _blockCipher.Initialize(true, KeyParam);

            byte[] iv = KeyParam.IV;

            if (iv.Length < _ofbIv.Length)
            {
                // prepend the supplied IV with zeros per FIPS PUB 81
                Array.Copy(iv, 0, _ofbIv, _ofbIv.Length - iv.Length, iv.Length);

                for (int i = 0; i < _ofbIv.Length - iv.Length; i++)
                    _ofbIv[i] = 0;
            }
            else
            {
                Array.Copy(iv, 0, _ofbIv, 0, _ofbIv.Length);
            }

            _isEncryption = Encryption;
            _isInitialized = true;
        }

        /// <summary>
        /// <para>Transform a block of bytes. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            ProcessBlock(Input, 0, Output, 0);
        }

        /// <summary>
        /// <para>Transform a block of bytes with offset parameters. 
        /// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            ProcessBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Private Methods
        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            _blockCipher.Transform(_ofbIv, 0, _ofbBuffer, 0);

            // xor the _ofbIv with the plaintext producing the cipher text and the next Input block
            for (int i = 0; i < _blockSize; i++)
                Output[OutOffset + i] = (byte)(_ofbBuffer[i] ^ Input[InOffset + i]);

            // change over the Input block.
            Buffer.BlockCopy(_ofbIv, _blockSize, _ofbIv, 0, _ofbIv.Length - _blockSize);
            Buffer.BlockCopy(_ofbBuffer, 0, _ofbIv, _ofbIv.Length - _blockSize, _blockSize);
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
                    if (_blockCipher != null && _disposeEngine)
                        _blockCipher.Dispose();

                    if (_ofbIv != null)
                    {
                        Array.Clear(_ofbIv, 0, _ofbIv.Length);
                        _ofbIv = null;
                    }
                    if (_ofbBuffer != null)
                    {
                        Array.Clear(_ofbBuffer, 0, _ofbBuffer.Length);
                        _ofbBuffer = null;
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
