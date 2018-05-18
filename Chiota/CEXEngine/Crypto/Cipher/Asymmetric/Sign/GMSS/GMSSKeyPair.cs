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
// An implementation of the Generalized Merkle Signature Scheme Asymmetric Signature Scheme.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle Based on the Bouncy Castle Java 
// <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.
// 
// Implementation Details:
// An implementation of an Generalized Merkle Signature Scheme. 
// Written by John Underhill, July 06, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS
{
    /// <summary>
    /// An Generalized Merkle Signature Scheme Key-Pair container
    /// </summary>
    public sealed class GMSSKeyPair : IAsymmetricKeyPair
    {
        #region Constants
        private const string ALG_NAME = "GMSSKeyPair";
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
        /// <exception cref="CryptoAsymmetricSignException">Thrown if an invalid key is used</exception>
        public GMSSKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            if (!(PublicKey is GMSSPublicKey))
                throw new CryptoAsymmetricSignException("GMSSKeyPair:Ctor", "Not a valid GMSS Public key!", new InvalidDataException());
            if (!(PrivateKey is GMSSPrivateKey))
                throw new CryptoAsymmetricSignException("GMSSKeyPair:Ctor", "Not a valid GMSS Private key!", new InvalidDataException());

            m_publicKey = (GMSSPublicKey)PublicKey;
            m_privateKey = (GMSSPrivateKey)PrivateKey;
            m_publicKey = PublicKey;
            m_privateKey = PrivateKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if an invalid key is used</exception>
        public GMSSKeyPair(IAsymmetricKey Key)
        {
            if (Key is GMSSPublicKey)
                m_publicKey = (GMSSPublicKey)Key;
            else if (Key is GMSSPrivateKey)
                m_privateKey = (GMSSPrivateKey)Key;
            else
                throw new CryptoAsymmetricSignException("GMSSKeyPair:Ctor", "Not a valid GMSS key!", new InvalidDataException());
        }

        private GMSSKeyPair()
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
            return new GMSSKeyPair((IAsymmetricKey)m_publicKey.Clone(), (IAsymmetricKey)m_privateKey.Clone());
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
                        ((GMSSPrivateKey)m_privateKey).Dispose();
                    if (m_publicKey != null)
                        ((GMSSPublicKey)m_publicKey).Dispose();
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
