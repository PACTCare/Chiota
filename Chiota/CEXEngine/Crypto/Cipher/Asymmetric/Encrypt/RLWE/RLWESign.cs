#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
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
    /// An Ring-LWE One Time Sign (OTS) message sign and verify implementation.
    /// <para>Sign: uses the specified digest to hash a message; the hash value is then encrypted with a RLWE public key.
    /// Verify: decrypts the RLWE cipher text, and then compares the value to a hash of the message.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of using the signing and verifying an array:</description>
    /// <code>
    /// RLWEParameters ps = RLWEParamSets.RLWEN256Q768;
    /// RLWEKeyGenerator gen = new RLWEKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// byte[] code;
    /// byte[] data = new byte[100];
    ///
    /// // get the message code for an array of bytes
    /// using (RLWESign sgn = new RLWESign(ps))
    /// {
    ///     sgn.Initialize(new RLWEKeyPair(kp.PublicKey));
    ///     code = sgn.Sign(data, 0, data.Length);
    /// }
    ///
    /// // authenticate the message
    /// using (RLWESign sgn = new RLWESign(ps))
    /// {
    ///     sgn.Initialize(new RLWEKeyPair(kp.PrivateKey));
    ///     bool valid = sgn.Verify(data, 0, data.Length, code);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Signing is intended as a one time only key implementation (OTS); keys should never be re-used.</description></item>
    /// <item><description>Digests can be any of the implemented digests; Blake, Keccak, SHA-2 or Skein.</description></item>
    /// </list>
    /// </remarks>
    public sealed class RLWESign : IAsymmetricSign
    {
        #region Constants
        private const string ALG_NAME = "RLWESign";
        #endregion

        #region Fields
        private RLWEEncrypt m_asyCipher;
        private IAsymmetricKey m_asmKey;
        private IDigest m_dgtEngine;
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        public bool IsInitialized
        {
            get { return m_isInitialized; }
        }

        /// <summary>
        /// Get: This class is initialized for Signing with the Public key
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if cipher has not been initialized</exception>
        public bool IsSigner
        {
            get
            {
                if (!m_isInitialized)
                    throw new CryptoAsymmetricSignException("RLWESign:IsSigner", "The signer has not been initialized!", new InvalidOperationException());

                return (m_asmKey is RLWEPublicKey);
            }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized</exception>
        public int MaxPlainText
        {
            get 
            { 
                if (!m_isInitialized)
                    throw new CryptoAsymmetricException("RLWESign:MaxPlainText", "The signer has not been initialized!", new InvalidOperationException());

                if (m_asmKey is RLWEPublicKey)
                    return ((RLWEPublicKey)m_asmKey).N >> 3; 
                else
                    return ((RLWEPrivateKey)m_asmKey).N >> 3; 
            }
        }

        /// <summary>
        /// Get: Signer name
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
        /// 
        /// <param name="CipherParams">The RLWE cipher used to encrypt the hash</param>
        /// <param name="Digest">The type of digest engine used</param>
        public RLWESign(RLWEParameters CipherParams, Digests Digest = Digests.SHA512)
        {
            m_asyCipher = new RLWEEncrypt(CipherParams);
            m_dgtEngine = GetDigest(Digest);
        }

        private RLWESign()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWESign()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the RLWE Public (Sign) or Private (Verify) key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key pair is used</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is RLWEPublicKey) && !(AsmKey is RLWEPrivateKey))
                throw new CryptoAsymmetricException("RLWESign:Initialize", "The key is not a valid Ring-LWE key!", new InvalidDataException());

            Reset();
            m_asmKey = AsmKey;
            m_isInitialized = true;
        }

        /// <summary>
        /// Reset the underlying digest engine
        /// </summary>
        public void Reset()
        {
            m_dgtEngine.Reset();
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key pair is used, or signer has not been initialized</exception>
        public byte[] Sign(Stream InputStream)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWESign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RLWEPublicKey))
                throw new CryptoAsymmetricException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);

            if (m_asyCipher.MaxPlainText < m_dgtEngine.DigestSize)
                throw new CryptoAsymmetricException("RLWESign:Sign", String.Format("The key size is too small; key supports encrypting up to {0} bytes!", m_asyCipher.MaxPlainText), new ArgumentException());

            byte[] hash = Compute(InputStream);

            return m_asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="Input">The byte array contining the data</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if input array is too short, signer is not initialized, or keys are invalid</exception>
        public byte[] Sign(byte[] Input, int Offset, int Length)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricException("RLWESign:Sign", "The input array is too short!", new ArgumentException());
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWESign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RLWEPublicKey))
                throw new CryptoAsymmetricException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);

            if (m_asyCipher.MaxPlainText < m_dgtEngine.DigestSize)
                throw new CryptoAsymmetricException("RLWESign:Sign", String.Format("The key size is too small; key supports encrypting up to {0} bytes!", m_asyCipher.MaxPlainText), new InvalidDataException());

            byte[] hash = Compute(Input, Offset, Length);

            return m_asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data to test</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if signer is not initialized, or keys are invalid</exception>
        public bool Verify(Stream InputStream, byte[] Code)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWESign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RLWEPrivateKey))
                throw new CryptoAsymmetricException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);
            byte[] chksum = m_asyCipher.Decrypt(Code);
            byte[] hash = Compute(InputStream);

            return Compare.IsEqual(hash, chksum);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="Input">The stream containing the data to test</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if input array is too short, signer is not initialized, or keys are invalid</exception>
        public bool Verify(byte[] Input, int Offset, int Length, byte[] Code)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricException("RLWESign:Verify", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!m_isInitialized)
                throw new CryptoAsymmetricException("RLWESign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RLWEPrivateKey))
                throw new CryptoAsymmetricException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());

            m_asyCipher.Initialize(m_asmKey);
            byte[] chksum = m_asyCipher.Decrypt(Code);
            byte[] hash = Compute(Input, Offset, Length);

            return Compare.IsEqual(hash, chksum);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Compute the hash from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(Stream InputStream)
        {
            int length = (int)(InputStream.Length - InputStream.Position);
            int blockSize = m_dgtEngine.BlockSize < length ? length : m_dgtEngine.BlockSize;
            int bytesRead = 0;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                bytesRead = InputStream.Read(buffer, 0, blockSize);
                m_dgtEngine.BlockUpdate(buffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            // last block
            if (bytesTotal < length)
            {
                buffer = new byte[length - bytesTotal];
                bytesRead = InputStream.Read(buffer, 0, buffer.Length);
                m_dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
                bytesTotal += buffer.Length;
            }

            byte[] hash = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Compute the hash from a byte array
        /// </summary>
        /// 
        /// <param name="Input">The data byte array</param>
        /// <param name="Offset">The starting offset within the array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(byte[] Input, int Offset, int Length)
        {
            if (Length < Input.Length - Offset)
                throw new ArgumentOutOfRangeException();

            int blockSize = m_dgtEngine.BlockSize < Length ? Length : m_dgtEngine.BlockSize;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = Length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, blockSize);
                m_dgtEngine.BlockUpdate(buffer, 0, blockSize);
                bytesTotal += blockSize;
            }

            // last block
            if (bytesTotal < Length)
            {
                buffer = new byte[Length - bytesTotal];
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, Math.Min(buffer.Length, Input.Length - bytesTotal));
                m_dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
            }

            byte[] hash = new byte[m_dgtEngine.DigestSize];
            m_dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="DigestType">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoAsymmetricException("RLWESign:GetDigest", "The digest type is not unsupported!", new ArgumentException());
            }
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
                    if (m_dgtEngine != null)
                    {
                        m_dgtEngine.Dispose();
                        m_dgtEngine = null;
                    }
                    if (m_asyCipher != null)
                    {
                        m_asyCipher.Dispose();
                        m_asyCipher = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
