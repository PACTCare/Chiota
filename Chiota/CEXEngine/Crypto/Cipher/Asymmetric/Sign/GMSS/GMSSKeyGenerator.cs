#region Directives
using System;
using System.Collections.Generic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
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
    /// An Generalized Merkle Signature Scheme Signature Scheme Key-Pair Generator
    /// </summary>
    ///
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// GMSSKeyGenerator encParams = (GMSSParameters)GMSSParamSets.GMSSN2P10.DeepCopy();
    /// GMSSKeyGenerator keyGen = new GMSSKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.GMSSSign"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.GMSSPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.GMSSPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Selecting Parameters for the <a href="https://www.cdc.informatik.tu-darmstadt.de/reports/reports/BDKOV07.pdf">Generalized Merkle Signature Scheme Signature Scheme</a></description></item>
    /// </list>
    /// </remarks>
    public sealed class GMSSKeyGenerator : IAsymmetricGenerator
    {
        #region Constants
        private const string ALG_NAME = "GMSSKeyGenerator";
        #endregion

        #region Fields
        private bool m_isDisposed;
        private GMSSParameters _gmssParams;
        // The source of randomness for OTS private key generation
        private GMSSRandom _gmssRand;
        // The hash function used for the construction of the authentication trees
        private IDigest _msDigestTree;
        // An array of the seeds for the PRGN (for main tree, and all current subtrees)
        private byte[][] _currentSeeds;
        // An array of seeds for the PRGN (for all subtrees after next)
        private byte[][] _nextNextSeeds;
        // An array of the RootSignatures
        private byte[][] _currentRootSigs;
        // The length of the seed for the PRNG
        private int _mdLength;
        // the number of Layers
        private int _numLayer;
        // An array of the heights of the authentication trees of each layer
        private int[] _heightOfTrees;
        // An array of the Winternitz parameter 'w' of each layer
        private int[] _otsIndex;
        // The parameter K needed for the authentication path computation
        private int[] m_K;
        private Digests _msgDigestType;
        private Prngs m_rndEngineType;
        private IRandom m_rndEngine;
        #endregion

        #region Properties

        /// <summary>
        /// Get: Generator name
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
        /// <param name="CiphersParams">The GMSSParameters instance containing the cipher settings</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if a Prng that requires pre-initialization is specified; (wrong constructor)</exception>
        public GMSSKeyGenerator(GMSSParameters CiphersParams)
        {
            if (CiphersParams.RandomEngine == Prngs.PBPrng)
                throw new CryptoAsymmetricSignException("GMSSKeyGenerator:Ctor", "Passphrase based digest and CTR generators must be pre-initialized, use the other constructor!", new ArgumentException());

            _gmssParams = CiphersParams;
            _msgDigestType = CiphersParams.DigestEngine;
            m_rndEngineType = _gmssParams.RandomEngine;
            _msDigestTree = GetDigest(CiphersParams.DigestEngine);
            // construct randomizer
            _gmssRand = new GMSSRandom(_msDigestTree);
            // set mdLength
            _mdLength = _msDigestTree.DigestSize;
            // construct Random for initial seed generation
            m_rndEngine = GetPrng(m_rndEngineType);

            Initialize();
        }

        /// <summary>
        /// Use an initialized prng to generate the key; use this constructor with an Rng that requires pre-initialization, i.e. PBPrng
        /// </summary>
        /// 
        /// <param name="CiphersParams">The GMSSParameters instance containing the cipher settings</param>
        /// <param name="RngEngine">An initialized random generator instance</param>
        public GMSSKeyGenerator(GMSSParameters CiphersParams, IRandom RngEngine)
        {
            _gmssParams = CiphersParams;
            _msgDigestType = CiphersParams.DigestEngine;
            m_rndEngineType = _gmssParams.RandomEngine;
            _msDigestTree = GetDigest(CiphersParams.DigestEngine);
            // construct randomizer
            _gmssRand = new GMSSRandom(_msDigestTree);
            // set mdLength
            _mdLength = _msDigestTree.DigestSize;
            // construct Random for initial seed generation
            m_rndEngine = RngEngine;

            Initialize();
        }

        private GMSSKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSKeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A GMSSKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            // initialize authenticationPaths and treehash instances
            byte[][][] currentAuthPaths = new byte[_numLayer][][];
            byte[][][] nextAuthPaths = new byte[_numLayer - 1][][];
            Treehash[][] currentTreehash = new Treehash[_numLayer][];
            Treehash[][] nextTreehash = new Treehash[_numLayer - 1][];
            List<byte[]>[] currentStack = new List<byte[]>[_numLayer];
            List<byte[]>[] nextStack = new List<byte[]>[_numLayer - 1];
            List<byte[]>[][] currentRetain = new List<byte[]>[_numLayer][];
            List<byte[]>[][] nextRetain = new List<byte[]>[_numLayer - 1][];

            for (int i = 0; i < _numLayer; i++)
            {
                currentAuthPaths[i] = ArrayUtils.CreateJagged<byte[][]>(_heightOfTrees[i], _mdLength);//new byte[heightOfTrees[i]][mdLength];
                currentTreehash[i] = new Treehash[_heightOfTrees[i] - m_K[i]];

                if (i > 0)
                {
                    nextAuthPaths[i - 1] = ArrayUtils.CreateJagged<byte[][]>(_heightOfTrees[i], _mdLength);//new byte[heightOfTrees[i]][mdLength];
                    nextTreehash[i - 1] = new Treehash[_heightOfTrees[i] - m_K[i]];
                }

                currentStack[i] = new List<byte[]>();
                if (i > 0)
                    nextStack[i - 1] = new List<byte[]>();
            }

            // initialize roots
            byte[][] currentRoots = ArrayUtils.CreateJagged<byte[][]>(_numLayer, _mdLength);
            byte[][] nextRoots = ArrayUtils.CreateJagged<byte[][]>(_numLayer - 1, _mdLength);
            // initialize seeds
            byte[][] seeds = ArrayUtils.CreateJagged<byte[][]>(_numLayer, _mdLength);

            // initialize seeds[] by copying starting-seeds of first trees of each layer
            for (int i = 0; i < _numLayer; i++)
                Array.Copy(_currentSeeds[i], 0, seeds[i], 0, _mdLength);

            // initialize rootSigs
            _currentRootSigs = ArrayUtils.CreateJagged<byte[][]>(_numLayer - 1, _mdLength);//new byte[numLayer - 1][mdLength];

            // calculation of current authpaths and current rootsigs (AUTHPATHS, SIG) from bottom up to the root
            for (int h = _numLayer - 1; h >= 0; h--)
            {
                GMSSRootCalc tree = new GMSSRootCalc(_heightOfTrees[h], m_K[h], GetDigest(_msgDigestType));
                try
                {
                    // on lowest layer no lower root is available, so just call the method with null as first parameter
                    if (h == _numLayer - 1)
                        tree = GenerateCurrentAuthpathAndRoot(null, currentStack[h], seeds[h], h);
                    else
                        // otherwise call the method with the former computed root value
                        tree = GenerateCurrentAuthpathAndRoot(currentRoots[h + 1], currentStack[h], seeds[h], h);

                }
                catch
                {
                }

                // set initial values needed for the private key construction
                for (int i = 0; i < _heightOfTrees[h]; i++)
                    Array.Copy(tree.GetAuthPath()[i], 0, currentAuthPaths[h][i], 0, _mdLength);
                
                currentRetain[h] = tree.GetRetain();
                currentTreehash[h] = tree.GetTreehash();
                Array.Copy(tree.GetRoot(), 0, currentRoots[h], 0, _mdLength);
            }

            // calculation of next authpaths and next roots (AUTHPATHS+, ROOTS+)
            for (int h = _numLayer - 2; h >= 0; h--)
            {
                GMSSRootCalc tree = GenerateNextAuthpathAndRoot(nextStack[h], seeds[h + 1], h + 1);

                // set initial values needed for the private key construction
                for (int i = 0; i < _heightOfTrees[h + 1]; i++)
                    Array.Copy(tree.GetAuthPath()[i], 0, nextAuthPaths[h][i], 0, _mdLength);

                nextRetain[h] = tree.GetRetain();
                nextTreehash[h] = tree.GetTreehash();
                Array.Copy(tree.GetRoot(), 0, nextRoots[h], 0, _mdLength);
                // create seed for the Merkle tree after next (nextNextSeeds) SEEDs++
                Array.Copy(seeds[h + 1], 0, _nextNextSeeds[h], 0, _mdLength);
            }

            // generate JDKGMSSPublicKey 
            int[] len = new int[] { currentRoots[0].Length };
            byte[] btlen = new byte[4];
            Buffer.BlockCopy(len, 0, btlen, 0, btlen.Length);

            GMSSPublicKey pubKey = new GMSSPublicKey(ArrayUtils.Concat(btlen, currentRoots[0]));

            // generate the JDKGMSSPrivateKey
            GMSSPrivateKey privKey = new GMSSPrivateKey(_currentSeeds, _nextNextSeeds, currentAuthPaths, nextAuthPaths, currentTreehash, 
                nextTreehash, currentStack, nextStack, currentRetain, nextRetain, nextRoots, _currentRootSigs, _gmssParams, _msgDigestType);

            // return the KeyPair
            return new GMSSKeyPair(pubKey, privKey);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Calculates the authpath for tree in layer h which starts with seed[h] additionally computes the rootSignature of underlaying root
        /// </summary>
        /// 
        /// <param name="LowerRoot">Stores the root of the lower tree</param>
        /// <param name="CurrentStack">Stack used for the treehash instance created by this method</param>
        /// <param name="Seed">Starting seeds</param>
        /// <param name="H">Actual layer</param>
        /// <returns>An initialized GMSSRootCalc</returns>
        private GMSSRootCalc GenerateCurrentAuthpathAndRoot(byte[] LowerRoot, List<byte[]> CurrentStack, byte[] Seed, int H)
        {
            byte[] help = new byte[_mdLength];
            byte[] OTSseed = new byte[_mdLength];
            OTSseed = _gmssRand.NextSeed(Seed);
            WinternitzOTSignature ots;
            // data structure that constructs the whole tree and stores the initial values for treehash, Auth and retain
            GMSSRootCalc treeToConstruct = new GMSSRootCalc(_heightOfTrees[H], m_K[H], GetDigest(_msgDigestType));
            treeToConstruct.Initialize(CurrentStack);

            // generate the first leaf
            if (H == _numLayer - 1)
            {
                ots = new WinternitzOTSignature(OTSseed, GetDigest(_msgDigestType), _otsIndex[H]);
                help = ots.GetPublicKey();
            }
            else
            {
                // for all layers except the lowest, generate the signature of the underlying root
                // and reuse this signature to compute the first leaf of acual layer more efficiently (by verifiing the signature)
                ots = new WinternitzOTSignature(OTSseed, GetDigest(_msgDigestType), _otsIndex[H]);
                _currentRootSigs[H] = ots.GetSignature(LowerRoot);
                WinternitzOTSVerify otsver = new WinternitzOTSVerify(GetDigest(_msgDigestType), _otsIndex[H]);
                help = otsver.Verify(LowerRoot, _currentRootSigs[H]);
            }

            // update the tree with the first leaf
            treeToConstruct.Update(help);
            int seedForTreehashIndex = 3;
            int count = 0;

            // update the tree 2^(H) - 1 times, from the second to the last leaf
            for (int i = 1; i < (1 << _heightOfTrees[H]); i++)
            {
                // initialize the seeds for the leaf generation with index 3 * 2^h
                if (i == seedForTreehashIndex && count < _heightOfTrees[H] - m_K[H])
                {
                    treeToConstruct.InitializeTreehashSeed(Seed, count);
                    seedForTreehashIndex *= 2;
                    count++;
                }

                OTSseed = _gmssRand.NextSeed(Seed);
                ots = new WinternitzOTSignature(OTSseed, GetDigest(_msgDigestType), _otsIndex[H]);
                treeToConstruct.Update(ots.GetPublicKey());
            }

            if (treeToConstruct.IsFinished())
                return treeToConstruct;

            return null;
        }

        /// <summary>
        /// Calculates the authpath and root for tree in layer h which starts with seed[h]
        /// </summary>
        /// 
        /// <param name="NextStack">Stack used for the treehash instance created by this method</param>
        /// <param name="Seed">Starting seeds</param>
        /// <param name="H">Actual layer</param>
        /// 
        /// <returns>An initialized GMSSRootCalc</returns>
        private GMSSRootCalc GenerateNextAuthpathAndRoot(List<byte[]> NextStack, byte[] Seed, int H)
        {
            byte[] OTSseed = new byte[_numLayer];
            WinternitzOTSignature ots;

            // data structure that constructs the whole tree and stores the initial values for treehash, Auth and retain
            GMSSRootCalc treeToConstruct = new GMSSRootCalc(_heightOfTrees[H], m_K[H], GetDigest(_msgDigestType));
            treeToConstruct.Initialize(NextStack);
            int seedForTreehashIndex = 3;
            int count = 0;

            // update the tree 2^(H) times, from the first to the last leaf
            for (int i = 0; i < (1 << _heightOfTrees[H]); i++)
            {
                // initialize the seeds for the leaf generation with index 3 * 2^h
                if (i == seedForTreehashIndex && count < _heightOfTrees[H] - m_K[H])
                {
                    treeToConstruct.InitializeTreehashSeed(Seed, count);
                    seedForTreehashIndex *= 2;
                    count++;
                }

                OTSseed = _gmssRand.NextSeed(Seed);
                ots = new WinternitzOTSignature(OTSseed, GetDigest(_msgDigestType), _otsIndex[H]);
                treeToConstruct.Update(ots.GetPublicKey());
            }

            if (treeToConstruct.IsFinished())
                return treeToConstruct;

            return null;
        }

        /// <summary>
        /// Initalizes the key pair generator using a parameter set as input
        /// </summary>
        private void Initialize()
        {
            _numLayer = _gmssParams.NumLayers;
            _heightOfTrees = _gmssParams.HeightOfTrees;
            _otsIndex = _gmssParams.WinternitzParameter;
            m_K = _gmssParams.K;

            // seeds
            _currentSeeds = ArrayUtils.CreateJagged<byte[][]>(_numLayer, _mdLength);
            _nextNextSeeds = ArrayUtils.CreateJagged<byte[][]>(_numLayer - 1, _mdLength);

            // generation of initial seeds
            for (int i = 0; i < _numLayer; i++)
            {
                m_rndEngine.GetBytes(_currentSeeds[i]);
                _gmssRand.NextSeed(_currentSeeds[i]);
            }
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
                throw new CryptoRandomException("GMSSKeyGenerator:GetDigest", "The digest type is not recognized!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="PrngType">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs PrngType)
        {
            try
            {
                return PrngFromName.GetInstance(PrngType);
            }
            catch
            {
                throw new CryptoAsymmetricSignException("GMSSKeyGenerator:GetPrng", "The Prng type is not supported!", new ArgumentException());
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
                    if (_gmssRand != null)
                    {
                        _gmssRand.Dispose();
                        _gmssRand = null;
                    }
                    if (m_rndEngine != null)
                    {
                        m_rndEngine.Dispose();
                        m_rndEngine = null;
                    }
                    if (_msDigestTree != null)
                    {
                        _msDigestTree.Dispose();
                        _msDigestTree = null;
                    }
                    if (_currentSeeds != null)
                    {
                        Array.Clear(_currentSeeds, 0, _currentSeeds.Length);
                        _currentSeeds = null;
                    }
                    if (_nextNextSeeds != null)
                    {
                        Array.Clear(_nextNextSeeds, 0, _nextNextSeeds.Length);
                        _nextNextSeeds = null;
                    }
                    if (_currentRootSigs != null)
                    {
                        Array.Clear(_currentRootSigs, 0, _currentRootSigs.Length);
                        _currentRootSigs = null;
                    }
                    if (_currentRootSigs != null)
                    {
                        Array.Clear(_currentRootSigs, 0, _currentRootSigs.Length);
                        _currentRootSigs = null;
                    }
                    _mdLength = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
