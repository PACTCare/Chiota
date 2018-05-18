#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
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
// Principal Algorithms:
// The Ring-LWE Asymmetric Cipher
// 
// Implementation Details:
// An implementation based on the description in the paper 'Efficient Software Implementation of Ring-LWE Encryption' 
// https://eprint.iacr.org/2014/725.pdf and accompanying Github project: https://github.com/ruandc/Ring-LWE-Encryption
// Written by John Underhill, June 8, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE
{
    /// <summary>
    /// An Ring-LWE Key-Pair container
    /// </summary>
    public sealed class RLWEKeyPair : IAsymmetricKeyPair
    {
        #region Constants
        private const string ALG_NAME = "RLWEKeyPair";
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private IAsymmetricKey m_publicKey;
        private IAsymmetricKey m_privateKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: KeyPair name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Returns the public key parameters
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return m_publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key parameters
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return m_privateKey; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="PublicKey">The public key</param>
        /// <param name="PrivateKey">The corresponding private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public RLWEKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            if (!(PublicKey is RLWEPublicKey))
                throw new CryptoAsymmetricException("RLWEKeyPair:Ctor", "Not a valid RLWE Public key!", new InvalidDataException());
            if (!(PrivateKey is RLWEPrivateKey))
                throw new CryptoAsymmetricException("RLWEKeyPair:Ctor", "Not a valid RLWE Private key!", new InvalidDataException());

            m_publicKey = (RLWEPublicKey)PublicKey;
            m_privateKey = (RLWEPrivateKey)PrivateKey;
            m_publicKey = PublicKey;
            m_privateKey = PrivateKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public RLWEKeyPair(IAsymmetricKey Key)
        {
            if (Key is RLWEPublicKey)
                m_publicKey = (RLWEPublicKey)Key;
            else if (Key is RLWEPrivateKey)
                m_privateKey = (RLWEPrivateKey)Key;
            else
                throw new CryptoAsymmetricException("RLWEKeyPair:Ctor", "Not a valid RLWE key!", new InvalidDataException());
        }
        
        /// <summary>
        /// Reads a key pair from an input stream.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key pair</param>
        public RLWEKeyPair(MemoryStream KeyStream)
        {
            m_publicKey = new RLWEPublicKey(KeyStream);
            m_privateKey = new RLWEPrivateKey(KeyStream);
        }

        /// <summary>
        /// Reads a key pair  from a byte array.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">An byte array containing an encoded key pair</param>
        public RLWEKeyPair(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private RLWEKeyPair()
        {
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this key pair instance
        /// </summary>
        /// 
        /// <returns>The IAsymmetricKeyPair copy</returns>
        public object Clone()
        {
            return new RLWEKeyPair((IAsymmetricKey)m_publicKey.Clone(), (IAsymmetricKey)m_privateKey.Clone());
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
                    if (m_privateKey != null)
                        ((RLWEPrivateKey)m_privateKey).Dispose();
                    if (m_publicKey != null)
                        ((RLWEPublicKey)m_publicKey).Dispose();
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
