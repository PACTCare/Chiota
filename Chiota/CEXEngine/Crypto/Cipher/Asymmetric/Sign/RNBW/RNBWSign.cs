#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.Arithmetic;
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
// An implementation of the Rainbow Asymmetric Signature Scheme.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle Based on the Bouncy Castle Java 
// <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.
// 
// Implementation Details:
// An implementation of an Rainbow Asymmetric Signature Scheme. 
// Written by John Underhill, July 06, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW
{
    /// <summary>
    /// An Rainbow Asymmetric Signature Scheme implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of using the signing and verifying an array:</description>
    /// <code>
    /// byte[] code;
    /// byte[] data = new byte[100];
    /// 
    /// RNBWParameters kpm = (RNBWParameters)RNBWParamSets.RNBWN33L5.DeepCopy();
    /// RNBWKeyGenerator gen = new RNBWKeyGenerator(kpm);
    /// IAsymmetricKeyPair keyPair = gen.GenerateKeyPair();
    ///
    /// // get the message code for an array of bytes
    /// using (RNBWSign sign = new RNBWSign(kpm))
    /// {
    ///     sign.Initialize(kp.PrivateKey);
    ///     code = sign.Sign(data, 0, data.Length);
    /// }
    ///
    /// // test the message for validity
    /// using (RNBWSign sign = new RNBWSign(kpm))
    /// {
    ///     sign.Initialize(kp.PublicKey);
    ///     bool valid = sign.Verify(data, 0, data.Length, code);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWSign"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Selecting Parameters for the <a href="http://eprint.iacr.org/2010/437.pdf">Rainbow Signature Scheme</a></description></item>
    /// </list>
    /// </remarks>
    public sealed class RNBWSign : IAsymmetricSign
    {
        #region Constants
        private const string ALG_NAME = "RNBWSign";
        #endregion

        #region Fields
        private IAsymmetricKey m_asmKey;
        private ComputeInField _cptIf = new ComputeInField();
        private IDigest m_dgtEngine;
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        private IRandom m_rndEngine;
        int _signableLength;
        private short[] m_X;
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
        /// Get: This class is initialized for Signing with the Private key
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if cipher has not been initialized</exception>
        public bool IsSigner
        {
            get 
            { 
                if (!m_isInitialized)
                    throw new CryptoAsymmetricSignException("RNBWSign:IsSigner", "The signer has not been initialized!", new InvalidOperationException());

                return (m_asmKey is RNBWPrivateKey);
            }
        }

        /// <summary>
        /// Get: The Signer name
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
        /// <param name="CipherParams">The RNBW cipher used to encrypt the hash</param>
        public RNBWSign(RNBWParameters CipherParams)
        {
            m_rndEngine = GetPrng(CipherParams.RandomEngine);
            _signableLength = CipherParams.DocLength;
        }

        private RNBWSign()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RNBWSign()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Key for Sign (Private) or Verify (Public)
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the Rainbow Public (verify) or Private (sign) key</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if an invalid key is used</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is RNBWPublicKey) && !(AsmKey is RNBWPrivateKey))
                throw new CryptoAsymmetricSignException("RNBWSign:Initialize", "The key pair is not a valid RNBW key pair!", new InvalidDataException());

            Reset();
            m_asmKey = AsmKey;
            m_isInitialized = true;
        }

        /// <summary>
        /// Reset the underlying digest engine
        /// </summary>
        public void Reset()
        {
            m_rndEngine.Reset();
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if an invalid key is used, or signer has not been initialized</exception>
        public byte[] Sign(Stream InputStream)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The private key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RNBWPrivateKey))
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The private key is invalid!", new InvalidDataException());

            byte[] data = ((MemoryStream)InputStream).ToArray();

            return GenerateSignature(data);
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
        /// <exception cref="CryptoAsymmetricSignException">Thrown if input array is too short, signer is not initialized, or the key is invalid</exception>
        public byte[] Sign(byte[] Input, int Offset, int Length)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The input array is too short!", new ArgumentException());
            if (!m_isInitialized)
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The private key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RNBWPrivateKey))
                throw new CryptoAsymmetricSignException("RNBWSign:Sign", "The private key is invalid!", new InvalidDataException());

            byte[] data = new byte[Length];
            Array.Copy(Input, Offset, data, 0, Length);

            return GenerateSignature(data);
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
        /// <exception cref="CryptoAsymmetricSignException">Thrown if signer is not initialized, or the key is invalid</exception>
        public bool Verify(Stream InputStream, byte[] Code)
        {
            if (!m_isInitialized)
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The public key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RNBWPublicKey))
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The public key is invalid!", new InvalidDataException());

            byte[] data = ((MemoryStream)InputStream).ToArray();

            return VerifySignature(data, Code);
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
        /// <exception cref="CryptoAsymmetricSignException">Thrown if input array is too short, signer is not initialized, or the key is invalid</exception>
        public bool Verify(byte[] Input, int Offset, int Length, byte[] Code)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!m_isInitialized)
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (m_asmKey == null)
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The public key is invalid!", new InvalidDataException());
            if (!(m_asmKey is RNBWPublicKey))
                throw new CryptoAsymmetricSignException("RNBWSign:Verify", "The public key is invalid!", new InvalidDataException());

            byte[] data = new byte[Length];
            Array.Copy(Input, Offset, data, 0, Length);

            return VerifySignature(data, Code);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Initial operations before solving the Linear equation system
        /// </summary>
        /// 
        /// <param name="Layer">The current layer for which a LES is to be solved</param>
        /// <param name="Message">The message that should be signed</param>
        /// 
        /// <returns>The modified document needed for solving LES, (Y_ = A1^{-1}*(Y-b1)) linear map L1 = A1 x + b1</returns>
        private short[] InitSign(MapLayer[] Layer, short[] Message)
        {

            // preparation: Modifies the document with the inverse of L1, tmp = Y - b1:
            short[] tmpVec = new short[Message.Length];
            tmpVec = _cptIf.AddVect(((RNBWPrivateKey)this.m_asmKey).B1, Message);
            // Y_ = A1^{-1} * (Y - b1) :
            short[] y = _cptIf.MultiplyMatrix(((RNBWPrivateKey)this.m_asmKey).InvA1, tmpVec);

            // generates the vinegar vars of the first layer at random
            for (int i = 0; i < Layer[0].VI; i++)
            {
                m_X[i] = (short)m_rndEngine.Next();
                m_X[i] = (short)(m_X[i] & GF2Field.MASK);
            }

            return y;
        }

        /// <summary>
        /// This function signs the message that has been updated, making use of the private key.
        /// <para>For computing the signature, L1 and L2 are needed, as well as LES should be solved 
        /// for each layer in order to find the Oil-variables in the layer.
        /// The Vinegar-variables of the first layer are random generated.</para>
        /// </summary>
        /// 
        /// <param name="Message">The message</param>
        /// 
        /// <returns>The signature of the message</returns>
        private byte[] GenerateSignature(byte[] Message)
        {
            MapLayer[] layer = ((RNBWPrivateKey)this.m_asmKey).Layers;
            int numberOfLayers = layer.Length;
            m_X = new short[((RNBWPrivateKey)this.m_asmKey).InvA2.Length]; // all variables
            short[] y;          // modified document
            short[] yi;         // part of Y_ each polynomial
            int counter;        // index of the current part of the doc
            short[] solVec;     // the solution of LES pro layer
            short[] tmpVec;
            short[] signature;  // the signature as an array of shorts:
            // the signature as a byte-array:
            byte[] S = new byte[layer[numberOfLayers - 1].ViNext];
            short[] msgHashVals = MakeMessageRepresentative(Message);

            // shows if an exception is caught
            bool ok;
            do
            {
                ok = true;
                counter = 0;
                try
                {
                    y = InitSign(layer, msgHashVals);

                    for (int i = 0; i < numberOfLayers; i++)
                    {
                        yi = new short[layer[i].OI];
                        solVec = new short[layer[i].OI]; // solution of LES

                        // copy oi elements of Y_ into y_i
                        for (int k = 0; k < layer[i].OI; k++)
                        {
                            yi[k] = y[counter];
                            counter++; // current index of Y_
                        }

                        // plug in the vars of the previous layer in order to get the vars of the current layer
                        solVec = _cptIf.SolveEquation(layer[i].PlugInVinegars(m_X), yi);

                        // LES is not solveable
                        if (solVec == null)
                            throw new Exception("LES is not solveable!");

                        // copy the new vars into the x-array
                        for (int j = 0; j < solVec.Length; j++)
                            m_X[layer[i].VI + j] = solVec[j];
                    }

                    // apply the inverse of L2: (signature = A2^{-1}*(b2+x)) 
                    tmpVec = _cptIf.AddVect(((RNBWPrivateKey)this.m_asmKey).B2, m_X);
                    signature = _cptIf.MultiplyMatrix(((RNBWPrivateKey)this.m_asmKey).InvA2, tmpVec);

                    // cast signature from short[] to byte[]
                    for (int i = 0; i < S.Length; i++)
                        S[i] = ((byte)signature[i]);
                }
                catch
                {
                    // if one of the LESs was not solveable - sign again
                    ok = false;
                }
            }
            while (!ok);

            // return the signature in bytes
            return S;
        }

        /// <summary>
        /// This function verifies the signature of the message that has been updated, with the aid of the public key
        /// </summary>
        /// 
        /// <param name="Message">The message</param>
        /// <param name="Signature">The signature of the message</param>
        /// 
        /// <returns>Returns true if the signature has been verified, false otherwise</returns>
        private bool VerifySignature(byte[] Message, byte[] Signature)
        {
            short[] sigInt = new short[Signature.Length];
            short tmp;

            for (int i = 0; i < Signature.Length; i++)
            {
                tmp = (short)Signature[i];
                tmp &= (short)0xff;
                sigInt[i] = tmp;
            }

            short[] msgHashVal = MakeMessageRepresentative(Message);
            // verify
            short[] verificationResult = VerifySignatureIntern(sigInt);
            // compare
            bool verified = true;

            if (msgHashVal.Length != verificationResult.Length)
                return false;

            for (int i = 0; i < msgHashVal.Length; i++)
                verified = verified && msgHashVal[i] == verificationResult[i];

            return verified;
        }

        /// <summary>
        /// Signature verification using public key
        /// </summary>
        /// 
        /// <param name="Signature">The signature vector of dimension n</param>
        /// <returns>Returns document hash of length n - v1</returns>
        private short[] VerifySignatureIntern(short[] Signature)
        {

            short[][] coeffQuadratic = ((RNBWPublicKey)this.m_asmKey).CoeffQuadratic;
            short[][] coeffSingular = ((RNBWPublicKey)this.m_asmKey).CoeffSingular;
            short[] coeffScalar = ((RNBWPublicKey)this.m_asmKey).CoeffScalar;

            short[] rslt = new short[coeffQuadratic.Length];// n - v1
            int n = coeffSingular[0].Length;
            int offset = 0; // array position
            short tmp = 0; // for scalar

            for (int p = 0; p < coeffQuadratic.Length; p++)
            {
                offset = 0;
                for (int x = 0; x < n; x++)
                {
                    // calculate quadratic terms
                    for (int y = x; y < n; y++)
                    {
                        tmp = GF2Field.MultElem(coeffQuadratic[p][offset], GF2Field.MultElem(Signature[x], Signature[y]));
                        rslt[p] = GF2Field.AddElem(rslt[p], tmp);
                        offset++;
                    }
                    // calculate singular terms
                    tmp = GF2Field.MultElem(coeffSingular[p][x], Signature[x]);
                    rslt[p] = GF2Field.AddElem(rslt[p], tmp);
                }
                // add scalar
                rslt[p] = GF2Field.AddElem(rslt[p], coeffScalar[p]);
            }

            return rslt;
        }

        /// <summary>
        /// This function creates the representative of the message which gets signed or verified
        /// </summary>
        /// 
        /// <param name="Message">The message</param>
        /// 
        /// <returns>Returns the message representative</returns>
        private short[] MakeMessageRepresentative(byte[] Message)
        {
            // the message representative
            short[] output = new short[this._signableLength];

            int h = 0;
            int i = 0;
            do
            {
                if (i >= Message.Length)
                    break;

                output[i] = (short)Message[h];
                output[i] &= (short)0xff;
                h++;
                i++;
            }
            while (i < output.Length);

            return output;
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="Prng">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.SP20Prng:
                    return new SP20Prng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPPrng:
                    return new CSPPrng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new CryptoAsymmetricSignException("RNBWEncrypt:GetPrng", "The Prng type is not supported!", new ArgumentException());
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
                    if (m_rndEngine != null)
                    {
                        m_rndEngine.Dispose();
                        m_rndEngine = null;
                    }
                    if (_cptIf != null)
                    {
                        _cptIf.Dispose();
                        _cptIf = null;
                    }
                    if (m_X != null)
                    {
                        Array.Clear(m_X, 0, m_X.Length);
                        m_X = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
