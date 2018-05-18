#region Directives
using System;
using System.Collections.Generic;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
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
    /// A Generalized Merkle Signature Scheme Private Key.
    /// <para>Each signing operation requires a unique sub-key.
    /// Use the <see cref="NextKey()"/> method to extract each new key subsequent to the initial key return.</para>
    /// </summary>
    public sealed class GMSSPrivateKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "GMSSPrivateKey";
        #endregion

        #region Fields
        private int[] _index;
        private byte[][] _currentSeeds;
        private byte[][] _nextNextSeeds;
        private byte[][][] _currentAuthPaths;
        private byte[][][] _nextAuthPaths;
        private Treehash[][] _currentTreehash;
        private Treehash[][] _nextTreehash;
        private List<byte[]>[] _currentStack;
        private List<byte[]>[] _nextStack;
        private List<byte[]>[][] _currentRetain;
        private List<byte[]>[][] _nextRetain;
        private byte[][][] _keep;
        private GMSSLeaf[] _nextNextLeaf;
        private GMSSLeaf[] _upperLeaf;
        private GMSSLeaf[] _upperTreehashLeaf;
        private int[] _minTreehash;
        private GMSSParameters _gmssPS;
        private byte[][] _nextRoot;
        private GMSSRootCalc[] _nextNextRoot;
        private byte[][] _currentRootSig;
        private GMSSRootSig[] _nextRootSig;
        private bool _isUsed = false;
        // An array of the heights of the authentication trees of each layer
        private int[] _heightOfTrees;
        // An array of the Winternitz parameter 'w' of each layer
        private int[] _otsIndex;
        // The parameter K needed for the authentication path computation
        private int[] m_K;
        // the number of Layers
        private int _numLayer;
        // The hash function used to construct the authentication trees
        private IDigest _msgDigestTrees;
        // The message digest length
        private int _mdLength;
        // The PRNG used for private key generation
        private GMSSRandom _gmssRandom;
        // The number of leafs of one tree of each layer
        private int[] _numLeafs;
        private Digests _msgDigestType;
        private bool m_isDisposed = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Private key name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: The current sub-key index
        /// </summary>
        public int[] Index
        {
            get { return _index; }
        }

        /// <summary>
        /// Get: The current seed values
        /// </summary>
        public byte[][] CurrentSeeds
        {
            get { return GMSSUtil.Clone(_currentSeeds); }
        }

        /// <summary>
        /// Get: The current Auth paths arrays
        /// </summary>
        public byte[][][] CurrentAuthPaths
        {
            get { return GMSSUtil.Clone(_currentAuthPaths); }
        }

        /// <summary>
        /// Get: The key deployment state
        /// </summary>
        public bool IsUsed
        {
            get { return _isUsed; }
            set { _isUsed = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the key with parameters
        /// </summary>
        /// 
        /// <param name="CurrentSeed">A seed for the generation of private OTS keys for the current subtrees</param>
        /// <param name="NextNextSeed">A seed for the generation of private OTS keys for the next subtrees</param>
        /// <param name="CurrentAuthPath">Array of current authentication paths</param>
        /// <param name="NextAuthPath">Array of next authentication paths</param>
        /// <param name="CurrentTreehash">Array of current treehash instances</param>
        /// <param name="NextTreehash">Array of next treehash instances</param>
        /// <param name="CurrentStack">Array of current shared stacks</param>
        /// <param name="NextStack">Array of next shared stacks</param>
        /// <param name="CurrentRetain">Array of current retain stacks</param>
        /// <param name="NextRetain">Array of next retain stacks</param>
        /// <param name="NextRoot">The roots of the next subtree</param>
        /// <param name="CurrentRootSig">Array of signatures of the roots of the current subtrees</param>
        /// <param name="ParameterSet">The GMSS Parameterset</param>
        /// <param name="Digest">The digest type</param>
        internal GMSSPrivateKey(byte[][] CurrentSeed, byte[][] NextNextSeed, byte[][][] CurrentAuthPath, byte[][][] NextAuthPath, Treehash[][] CurrentTreehash, 
            Treehash[][] NextTreehash, List<byte[]>[] CurrentStack, List<byte[]>[] NextStack, List<byte[]>[][] CurrentRetain, List<byte[]>[][] NextRetain, 
            byte[][] NextRoot, byte[][] CurrentRootSig, GMSSParameters ParameterSet, Digests Digest)
        :
            this(null, CurrentSeed, NextNextSeed, CurrentAuthPath, NextAuthPath, null, CurrentTreehash, NextTreehash, CurrentStack, NextStack,
                CurrentRetain, NextRetain, null, null, null, null, NextRoot, null, CurrentRootSig, null, ParameterSet, Digest)
        {
        }

        /// <summary>
        /// Initialize the key with parameters
        /// </summary>
        /// 
        /// <param name="Index">The tree indices</param>
        /// <param name="CurrentSeeds">A seed for the generation of private OTS keys for the current subtrees</param>
        /// <param name="NextNextSeeds">A seed for the generation of private OTS keys for the next subtrees</param>
        /// <param name="CurrentAuthPaths">Array of current authentication paths</param>
        /// <param name="NextAuthPaths">Array of next authentication paths</param>
        /// <param name="Keep">Keep array for the authPath algorithm</param>
        /// <param name="CurrentTreehash">Treehash for authPath algorithm of current tree</param>
        /// <param name="NextTreehash">Treehash for authPath algorithm of next tree (TREE+)</param>
        /// <param name="CurrentStack">Shared stack for authPath algorithm of current tree</param>
        /// <param name="NextStack">Shared stack for authPath algorithm of next tree (TREE+)</param>
        /// <param name="CurrentRetain">Retain stack for authPath algorithm of current tree</param>
        /// <param name="NextRetain">Retain stack for authPath algorithm of next tree (TREE+)</param>
        /// <param name="NextNextLeaf">Array of upcoming leafs of the tree after next (LEAF++) of each layer</param>
        /// <param name="UpperLeaf">Needed for precomputation of upper nodes</param>
        /// <param name="UpperTreehashLeaf">Needed for precomputation of upper treehash nodes</param>
        /// <param name="MinTreehash">Index of next treehash instance to receive an update</param>
        /// <param name="NextRoot">The roots of the next trees (ROOT+)</param>
        /// <param name="NextNextRoot">The roots of the tree after next (ROOT++)</param>
        /// <param name="CurrentRootSig">Array of signatures of the roots of the current subtrees (SIG)</param>
        /// <param name="NextRootSig">Array of signatures of the roots of the next subtree (SIG+)</param>
        /// <param name="ParameterSet">The GMSS Parameterset</param>
        /// <param name="Digest">The digest type</param>
        internal GMSSPrivateKey(int[] Index, byte[][] CurrentSeeds, byte[][] NextNextSeeds, byte[][][] CurrentAuthPaths, byte[][][] NextAuthPaths, byte[][][] Keep, 
            Treehash[][] CurrentTreehash, Treehash[][] NextTreehash, List<byte[]>[] CurrentStack, List<byte[]>[] NextStack, List<byte[]>[][] CurrentRetain, List<byte[]>[][] NextRetain,
            GMSSLeaf[] NextNextLeaf, GMSSLeaf[] UpperLeaf, GMSSLeaf[] UpperTreehashLeaf, int[] MinTreehash, byte[][] NextRoot, GMSSRootCalc[] NextNextRoot, byte[][] CurrentRootSig,
            GMSSRootSig[] NextRootSig, GMSSParameters ParameterSet, Digests Digest)
        {
            _msgDigestType = Digest;
            // construct message digest
            _msgDigestTrees = GetDigest(Digest);
            _mdLength = _msgDigestTrees.DigestSize;
            // Parameter
            _gmssPS = ParameterSet;
            _otsIndex = ParameterSet.WinternitzParameter;
            m_K = ParameterSet.K;
            _heightOfTrees = ParameterSet.HeightOfTrees;
            // initialize numLayer
            _numLayer = _gmssPS.NumLayers;

            // initialize index if null
            if (Index == null)
            {
                _index = new int[_numLayer];
                for (int i = 0; i < _numLayer; i++)
                    _index[i] = 0;
            }
            else
            {
                _index = Index;
            }

            _currentSeeds = CurrentSeeds;
            _nextNextSeeds = NextNextSeeds;
            _currentAuthPaths = CurrentAuthPaths;
            _nextAuthPaths = NextAuthPaths;

            // initialize keep if null
            if (Keep == null)
            {
                _keep = new byte[_numLayer][][];

                for (int i = 0; i < _numLayer; i++)
                    _keep[i] = ArrayUtils.CreateJagged<byte[][]>((int)Math.Floor((decimal)_heightOfTrees[i] / 2), _mdLength);
            }
            else
            {
                _keep = Keep;
            }

            // initialize stack if null
            if (CurrentStack == null)
            {
                _currentStack = new List<byte[]>[_numLayer];
                for (int i = 0; i < _numLayer; i++)
                    _currentStack[i] = new List<byte[]>();
            }
            else
            {
                _currentStack = CurrentStack;
            }

            // initialize nextStack if null
            if (NextStack == null)
            {
                _nextStack = new List<byte[]>[_numLayer - 1];
                for (int i = 0; i < _numLayer - 1; i++)
                    _nextStack[i] = new List<byte[]>();
            }
            else
            {
                _nextStack = NextStack;
            }

            _currentTreehash = CurrentTreehash;
            _nextTreehash = NextTreehash;
            _currentRetain = CurrentRetain;
            _nextRetain = NextRetain;
            _nextRoot = NextRoot;

            if (NextNextRoot == null)
            {
                NextNextRoot = new GMSSRootCalc[_numLayer - 1];
                for (int i = 0; i < _numLayer - 1; i++)
                    NextNextRoot[i] = new GMSSRootCalc(_heightOfTrees[i + 1], m_K[i + 1], GetDigest(Digest));
            }
            else
            {
                _nextNextRoot = NextNextRoot;
            }
            _currentRootSig = CurrentRootSig;

            // calculate numLeafs
            _numLeafs = new int[_numLayer];
            for (int i = 0; i < _numLayer; i++)
                _numLeafs[i] = 1 << _heightOfTrees[i];

            // construct PRNG
            _gmssRandom = new GMSSRandom(_msgDigestTrees);

            if (_numLayer > 1)
            {
                // construct the nextNextLeaf (LEAFs++) array for upcoming leafs in
                // tree after next (TREE++)
                if (NextNextLeaf == null)
                {
                    _nextNextLeaf = new GMSSLeaf[_numLayer - 2];
                    for (int i = 0; i < _numLayer - 2; i++)
                        _nextNextLeaf[i] = new GMSSLeaf(GetDigest(Digest), _otsIndex[i + 1], _numLeafs[i + 2], _nextNextSeeds[i]);
                }
                else
                {
                    _nextNextLeaf = NextNextLeaf;
                }
            }
            else
            {
                _nextNextLeaf = new GMSSLeaf[0];
            }

            // construct the upperLeaf array for upcoming leafs in tree over the
            // actual
            if (UpperLeaf == null)
            {
                _upperLeaf = new GMSSLeaf[_numLayer - 1];
                for (int i = 0; i < _numLayer - 1; i++)
                    _upperLeaf[i] = new GMSSLeaf(GetDigest(Digest), _otsIndex[i], _numLeafs[i + 1], _currentSeeds[i]);
            }
            else
            {
                _upperLeaf = UpperLeaf;
            }

            // construct the leafs for upcoming leafs in treehashs in tree over the actual
            if (UpperTreehashLeaf == null)
            {
                _upperTreehashLeaf = new GMSSLeaf[_numLayer - 1];
                for (int i = 0; i < _numLayer - 1; i++)
                    _upperTreehashLeaf[i] = new GMSSLeaf(GetDigest(Digest), _otsIndex[i], _numLeafs[i + 1]);
            }
            else
            {
                _upperTreehashLeaf = UpperTreehashLeaf;
            }

            if (MinTreehash == null)
            {
                _minTreehash = new int[_numLayer - 1];
                for (int i = 0; i < _numLayer - 1; i++)
                    _minTreehash[i] = -1;
            }
            else
            {
                _minTreehash = MinTreehash;
            }

            // construct the nextRootSig (RootSig++)
            byte[] dummy = new byte[_mdLength];
            byte[] OTSseed = new byte[_mdLength];

            if (NextRootSig == null)
            {
                _nextRootSig = new GMSSRootSig[_numLayer - 1];
                for (int i = 0; i < _numLayer - 1; i++)
                {
                    Array.Copy(CurrentSeeds[i], 0, dummy, 0, _mdLength);
                    _gmssRandom.NextSeed(dummy);
                    OTSseed = _gmssRandom.NextSeed(dummy);
                    _nextRootSig[i] = new GMSSRootSig(GetDigest(Digest), _otsIndex[i], _heightOfTrees[i + 1]);
                    _nextRootSig[i].InitSign(OTSseed, NextRoot[i]);
                }
            }
            else
            {
                _nextRootSig = NextRootSig;
            }
        }

        /// <summary>
        /// Copy Constructor
        /// </summary>
        /// 
        /// <param name="PrivateKey">The GMSSPrivateKey to copy</param>
        private GMSSPrivateKey(GMSSPrivateKey PrivateKey)
        {
            _index = ArrayUtils.Clone(PrivateKey._index);
            _currentSeeds = GMSSUtil.Clone(PrivateKey._currentSeeds);
            _nextNextSeeds = GMSSUtil.Clone(PrivateKey._nextNextSeeds);
            _currentAuthPaths = GMSSUtil.Clone(PrivateKey._currentAuthPaths);
            _nextAuthPaths = GMSSUtil.Clone(PrivateKey._nextAuthPaths);
            _keep = GMSSUtil.Clone(PrivateKey._keep);
            _currentTreehash = PrivateKey._currentTreehash;
            _nextTreehash = PrivateKey._nextTreehash;
            _currentStack = PrivateKey._currentStack;
            _nextStack = PrivateKey._nextStack;
            _currentRetain = PrivateKey._currentRetain;
            _nextRetain = PrivateKey._nextRetain;
            _nextNextLeaf = PrivateKey._nextNextLeaf; //N
            _upperLeaf = PrivateKey._upperLeaf; //N
            _upperTreehashLeaf = PrivateKey._upperTreehashLeaf; //N
            _minTreehash = PrivateKey._minTreehash; //N
            _nextRoot = GMSSUtil.Clone(PrivateKey._nextRoot);
            _nextNextRoot = PrivateKey._nextNextRoot; //N
            _currentRootSig = PrivateKey._currentRootSig;
            _nextRootSig = PrivateKey._nextRootSig; //N
            _gmssPS = PrivateKey._gmssPS;
            _msgDigestType = PrivateKey._msgDigestType;
            _heightOfTrees = PrivateKey._heightOfTrees;
            _otsIndex = PrivateKey._otsIndex;
            m_K = PrivateKey.m_K;
            _numLayer = PrivateKey._numLayer;
            _msgDigestTrees = PrivateKey._msgDigestTrees;
            _mdLength = PrivateKey._mdLength;
            _gmssRandom = PrivateKey._gmssRandom;
            _numLeafs = PrivateKey._numLeafs;
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if the key could not be loaded</exception>
        public GMSSPrivateKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len;
                int len2;
                byte[] data;

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _index = ArrayUtils.ToArray32(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _gmssPS = new GMSSParameters(data);

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _currentSeeds = ArrayUtils.CreateJagged<byte[][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _currentSeeds = ArrayUtils.ToArray2x8(data);
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _nextNextSeeds = ArrayUtils.CreateJagged<byte[][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _nextNextSeeds = ArrayUtils.ToArray2x8(data);
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _currentAuthPaths = ArrayUtils.CreateJagged<byte[][][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _currentAuthPaths = ArrayUtils.ToArray3x8(data);
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _nextAuthPaths = ArrayUtils.CreateJagged<byte[][][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _nextAuthPaths = ArrayUtils.ToArray3x8(data);
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _keep = ArrayUtils.CreateJagged<byte[][][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _keep = ArrayUtils.ToArray3x8(data);
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _currentTreehash = ArrayUtils.CreateJagged<Treehash[][]>(0, 0);
                }
                else
                {
                    len2 = reader.ReadInt32();
                    _currentTreehash = ArrayUtils.CreateJagged<Treehash[][]>(len, len2);
                    for (int i = 0; i < _currentTreehash.Length; i++)
                    {
                        for (int j = 0; j < _currentTreehash[i].Length; j++)
                        {
                            len = reader.ReadInt32();
                            data = reader.ReadBytes(len);
                            _currentTreehash[i][j] = new Treehash(GetDigest(_gmssPS.DigestEngine), data);
                        }
                    }
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _nextTreehash = ArrayUtils.CreateJagged<Treehash[][]>(0, 0);
                }
                else
                {
                    len2 = reader.ReadInt32();
                    _nextTreehash = ArrayUtils.CreateJagged<Treehash[][]>(len, len2);
                    for (int i = 0; i < _nextTreehash.Length; i++)
                    {
                        for (int j = 0; j < _nextTreehash[i].Length; j++)
                        {
                            len = reader.ReadInt32();
                            data = reader.ReadBytes(len);
                            _nextTreehash[i][j] = new Treehash(GetDigest(_gmssPS.DigestEngine), data);
                        }
                    }
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _currentStack = new List<byte[]>[0];
                }
                else
                {
                    _currentStack = new List<byte[]>[len];
                    for (int i = 0; i < _currentStack.Length; i++)
                    {
                        len = reader.ReadInt32();
                        data = reader.ReadBytes(len);
                        _currentStack[i].Add(data);
                    }
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _nextStack = new List<byte[]>[0];
                }
                else
                {
                    _nextStack = new List<byte[]>[len];
                    for (int i = 0; i < _nextStack.Length; i++)
                    {
                        len = reader.ReadInt32();
                        data = reader.ReadBytes(len);
                        _nextStack[i].Add(data);
                    }
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _currentRetain = ArrayUtils.CreateJagged<List<byte[]>[][]>(0, 0);
                }
                else
                {
                    len2 = reader.ReadInt32();
                    _currentRetain = ArrayUtils.CreateJagged<List<byte[]>[][]>(len, len2);
                    for (int i = 0; i < _currentRetain.Length; i++)
                    {
                        for (int j = 0; j < _currentRetain[i].Length; j++)
                        {
                            len = reader.ReadInt32();
                            data = reader.ReadBytes(len);
                            _currentRetain[i][j] = new List<byte[]>();
                            _currentRetain[i][j].Add(data);
                        }
                    }
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _nextRetain = ArrayUtils.CreateJagged<List<byte[]>[][]>(0, 0);
                }
                else
                {
                    len2 = reader.ReadInt32();
                    _nextRetain = ArrayUtils.CreateJagged<List<byte[]>[][]>(len, len2);
                    for (int i = 0; i < _nextRetain.Length; i++)
                    {
                        for (int j = 0; j < _nextRetain[i].Length; j++)
                        {
                            len = reader.ReadInt32();
                            data = reader.ReadBytes(len);
                            _nextRetain[i][j] = new List<byte[]>();
                            _nextRetain[i][j].Add(data);
                        }
                    }
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _nextRoot = ArrayUtils.CreateJagged<byte[][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _nextRoot = ArrayUtils.ToArray2x8(data);
                }

                len = reader.ReadInt32();
                if (len < 1)
                {
                    _currentRootSig = ArrayUtils.CreateJagged<byte[][]>(0, 0);
                }
                else
                {
                    data = reader.ReadBytes(len);
                    _currentRootSig = ArrayUtils.ToArray2x8(data);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("GMSSPrivateKey:CTor", "The GMSSPrivateKey could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public GMSSPrivateKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        private GMSSPrivateKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSPrivateKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Private key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized GMSSPrivateKey class</returns>
        public static GMSSPrivateKey From(byte[] KeyArray)
        {
            return new GMSSPrivateKey(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized GMSSPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static GMSSPrivateKey From(Stream KeyStream)
        {
            return new GMSSPrivateKey(KeyStream);
        }

        /// <summary>
        /// Get the next unused GMSS private key.
        /// <para>Use this call to get a new private key for each signing operation.</para>
        /// </summary>
        /// 
        /// <returns>The next available private key</returns>
        public GMSSPrivateKey NextKey()
        {
            GMSSPrivateKey nKey = new GMSSPrivateKey(this);
            nKey.NextKey(_gmssPS.NumLayers - 1);

            return nKey;
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded GMSSPrivateKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the GMSSPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] data;

            data = ArrayUtils.ToBytes(_index);
            writer.Write(data.Length);
            writer.Write(data);

            data = _gmssPS.ToBytes();
            writer.Write(data.Length);
            writer.Write(data);

            if (_currentSeeds.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_currentSeeds);
                writer.Write(data.Length);
                writer.Write(data);
            }

            if (_nextNextSeeds.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_nextNextSeeds);
                writer.Write(data.Length);
                writer.Write(data);
            }

            if (_currentAuthPaths.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_currentAuthPaths);
                writer.Write(data.Length);
                writer.Write(data);
            }

            if (_nextAuthPaths.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_nextAuthPaths);
                writer.Write(data.Length);
                writer.Write(data);
            }

            if (_keep.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_keep);
                writer.Write(data.Length);
                writer.Write(data);
            }

            if (_currentTreehash.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                writer.Write(_currentTreehash.Length);
                writer.Write(_currentTreehash[0].Length);
                for (int i = 0; i < _currentTreehash.Length; i++)
                {
                    for (int j = 0; j < _currentTreehash[i].Length; j++)
                    {
                        data = _currentTreehash[i][j].ToBytes();
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                }
            }

            if (_nextTreehash.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                writer.Write(_nextTreehash.Length);
                writer.Write(_nextTreehash[0].Length);
                for (int i = 0; i < _nextTreehash.Length; i++)
                {
                    for (int j = 0; j < _nextTreehash[i].Length; j++)
                    {
                        data = _nextTreehash[i][j].ToBytes();
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                }
            }

            if (_currentStack.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                if (_currentStack[0].Count == 0)
                {
                    writer.Write((int)0);
                }
                else
                {
                    writer.Write(_currentStack.Length);
                    for (int i = 0; i < _currentStack.Length; i++)
                    {
                        data = ArrayUtils.ToBytes(_currentStack[i].ToArray());
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                }
            }

            if (_nextStack.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                if (_nextStack[0].Count == 0)
                {
                    writer.Write((int)0);
                }
                else
                {
                    writer.Write(_nextStack.Length);
                    for (int i = 0; i < _nextStack.Length; i++)
                    {
                        data = ArrayUtils.ToBytes(_nextStack[i].ToArray());
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                }
            }

            if (_currentRetain.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                writer.Write(_currentRetain.Length);
                writer.Write(_currentRetain[0].Length);
                for (int i = 0; i < _currentRetain.Length; i++)
                {
                    for (int j = 0; j < _currentRetain[i].Length; j++)
                    {
                        data = ArrayUtils.ToBytes(_currentRetain[i][j].ToArray());
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                }
            }

            if (_nextRetain.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                writer.Write(_nextRetain.Length);
                writer.Write(_nextRetain[0].Length);
                for (int i = 0; i < _nextRetain.Length; i++)
                {
                    for (int j = 0; j < _nextRetain[i].Length; j++)
                    {
                        data = ArrayUtils.ToBytes(_nextRetain[i][j].ToArray());
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                }
            }

            if (_nextRoot.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_nextRoot);
                writer.Write(data.Length);
                writer.Write(data);
            }

            if (_currentRootSig.Length < 1)
            {
                writer.Write((int)0);
            }
            else
            {
                data = ArrayUtils.ToBytes(_currentRootSig);
                writer.Write(data.Length);
                writer.Write(data);
            }

            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the GMSSPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded as a byte array</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the encoded GMSSPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded to a byte array</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("GMSSPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded GMSSPrivateKey to an output stream
        /// </summary>
        /// 
        /// <param name="Output">The Output Stream receiving the encoded Private Key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be written</exception>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException ex)
            {
                throw new CryptoAsymmetricException("GMSSPrivateKey:WriteTo", "The key could not be written!", ex);
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Computes the upcoming currentAuthpath of <c>layer</c> using the revisited authentication path computation of Dahmen/Schneider 2008
        /// </summary>
        /// 
        /// <param name="Layer">The actual layer</param>
        private void ComputeAuthPaths(int Layer)
        {
            int Phi = _index[Layer];
            int H = _heightOfTrees[Layer];
            int K = m_K[Layer];

            // update all nextSeeds for seed scheduling
            for (int i = 0; i < H - K; i++)
                _currentTreehash[Layer][i].UpdateNextSeed(_gmssRandom);

            // STEP 1 of Algorithm
            int Tau = HeightOfPhi(Phi);
            byte[] OTSseed = new byte[_mdLength];
            OTSseed = _gmssRandom.NextSeed(_currentSeeds[Layer]);

            // STEP 2 of Algorithm
            // if phi's parent on height tau + 1 if left node, store auth_tau in keep_tau
            int L = (IntUtils.URShift(Phi, (Tau + 1))) & 1;
            byte[] tempKeep = new byte[_mdLength];
            // store the keep node not in keep[layer][tau/2] because it might be in use
            // wait until the space is freed in step 4a
            if (Tau < H - 1 && L == 0)
                Array.Copy(_currentAuthPaths[Layer][Tau], 0, tempKeep, 0, _mdLength);

            byte[] help = new byte[_mdLength];
            // STEP 3 of Algorithm
            // if phi is left child, compute and store leaf for next currentAuthPath path,
            // (obtained by veriying current signature)
            if (Tau == 0)
            {
                // leaf calc
                if (Layer == _numLayer - 1)
                {
                    // lowest layer computes the necessary leaf completely at this time
                    WinternitzOTSignature ots = new WinternitzOTSignature(OTSseed, GetDigest(_msgDigestType), _otsIndex[Layer]);
                    help = ots.GetPublicKey();
                }
                else
                {
                    // other layers use the precomputed leafs in nextNextLeaf
                    byte[] dummy = new byte[_mdLength];
                    Array.Copy(_currentSeeds[Layer], 0, dummy, 0, _mdLength);
                    _gmssRandom.NextSeed(dummy);
                    help = _upperLeaf[Layer].GetLeaf();
                    _upperLeaf[Layer].InitLeafCalc(dummy);
                }
                Array.Copy(help, 0, _currentAuthPaths[Layer][0], 0, _mdLength);
            }
            else
            {
                // STEP 4a of Algorithm
                // get new left currentAuthPath node on height tau
                byte[] toBeHashed = new byte[_mdLength << 1];
                Array.Copy(_currentAuthPaths[Layer][Tau - 1], 0, toBeHashed, 0, _mdLength);
                // free the shared keep[layer][tau/2]
                Array.Copy(_keep[Layer][(int)Math.Floor((decimal)(Tau - 1) / 2)], 0, toBeHashed, _mdLength, _mdLength);
                _msgDigestTrees.BlockUpdate(toBeHashed, 0, toBeHashed.Length);
                _currentAuthPaths[Layer][Tau] = new byte[_msgDigestTrees.DigestSize];
                _msgDigestTrees.DoFinal(_currentAuthPaths[Layer][Tau], 0);

                // STEP 4b and 4c of Algorithm
                // copy right nodes to currentAuthPath on height 0..Tau-1
                for (int i = 0; i < Tau; i++)
                {
                    // STEP 4b of Algorithm 
                    // 1st: copy from treehashs
                    if (i < H - K)
                    {
                        if (_currentTreehash[Layer][i].IsFinished())
                        {
                            Array.Copy(_currentTreehash[Layer][i].GetFirstNode(), 0, _currentAuthPaths[Layer][i], 0, _mdLength);
                            _currentTreehash[Layer][i].Destroy();
                        }
                    }

                    // 2nd: copy precomputed values from Retain
                    if (i < H - 1 && i >= H - K)
                    {
                        if (_currentRetain[Layer][i - (H - K)].Count > 0)
                        {
                            // pop element from retain
                            Array.Copy(_currentRetain[Layer][i - (H - K)][_currentRetain[Layer][i - (H - K)].Count - 1], 0, _currentAuthPaths[Layer][i], 0, _mdLength);
                            _currentRetain[Layer][i - (H - K)].RemoveAt(_currentRetain[Layer][i - (H - K)].Count - 1);
                        }
                    }

                    // STEP 4c of Algorithm initialize new stack at heights 0..Tau-1 
                    if (i < H - K)
                    {
                        // create stacks anew
                        int startPoint = Phi + 3 * (1 << i);
                        if (startPoint < _numLeafs[Layer])
                            _currentTreehash[Layer][i].Initialize();
                    }
                }
            }

            // now keep space is free to use
            if (Tau < H - 1 && L == 0)
            {
                Array.Copy(tempKeep, 0, _keep[Layer][(int)Math.Floor((decimal)Tau / 2)], 0, _mdLength);
            }

            // only update empty stack at height h if all other stacks have
            // tailnodes with height >h
            // finds active stack with lowest node height, choses lower index in
            // case of tie on the lowest layer leafs must be computed at once, no precomputation
            // is possible. So all treehash updates are done at once here
            if (Layer == _numLayer - 1)
            {
                for (int tmp = 1; tmp <= (H - K) / 2; tmp++)
                {
                    // index of the treehash instance that receives the next update
                    int minTreehash = GetMinTreehashIndex(Layer);

                    // if active treehash is found update with a leaf
                    if (minTreehash >= 0)
                    {
                        try
                        {
                            byte[] seed = new byte[_mdLength];
                            Array.Copy(_currentTreehash[Layer][minTreehash].GetSeedActive(), 0, seed, 0, _mdLength);
                            byte[] seed2 = _gmssRandom.NextSeed(seed);
                            WinternitzOTSignature ots = new WinternitzOTSignature(seed2, GetDigest(_msgDigestType), _otsIndex[Layer]);
                            byte[] leaf = ots.GetPublicKey();
                            _currentTreehash[Layer][minTreehash].Update(_gmssRandom, leaf);
                        }
                        catch
                        {
                        }
                    }
                }
            }
            else
            {
                // on higher layers the updates are done later
                _minTreehash[Layer] = GetMinTreehashIndex(Layer);
            }
        }

        internal int GetCurrentIndex(int Index)
        {
            return _index[Index];
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
                throw new CryptoRandomException("GMSSPrivateKey:GetDigest", "The digest type is not recognized!", new ArgumentException());
            }
        }

        internal int GetNumLeafs(int Index)
        {
            return _numLeafs[Index];
        }

        /// <summary>
        /// This method returns the index of the next Treehash instance that should receive an update
        /// </summary>
        /// 
        /// <param name="Layer">The layer of the GMSS tree</param>
        /// 
        /// <returns>Return index of the treehash instance that should get the update</returns>
        private int GetMinTreehashIndex(int Layer)
        {
            int minTreehash = -1;

            for (int h = 0; h < _heightOfTrees[Layer] - m_K[Layer]; h++)
            {
                if (_currentTreehash[Layer][h].IsInitialized() && !_currentTreehash[Layer][h].IsFinished())
                {
                    if (minTreehash == -1)
                        minTreehash = h;
                    else if (_currentTreehash[Layer][h].GetLowestNodeHeight() < _currentTreehash[Layer][minTreehash].GetLowestNodeHeight())
                        minTreehash = h;
                }
            }

            return minTreehash;
        }

        /// <summary>
        /// Returns the largest h such that 2^h | Phi
        /// </summary>
        /// 
        /// <param name="Phi">The leaf index</param>
        /// 
        /// <returns>Return The largest <c>h</c> with <c>2^h | Phi</c> if <c>Phi!=0</c> else return <c>-1</c></returns>
        private int HeightOfPhi(int Phi)
        {
            if (Phi == 0)
                return -1;

            int Tau = 0;
            int modul = 1;

            while (Phi % modul == 0)
            {
                modul *= 2;
                Tau += 1;
            }

            return Tau - 1;
        }

        /// <summary>
        /// This method updates the GMSS private key for the next signature
        /// </summary>
        /// 
        /// <param name="Layer">The layer where the next key is processed</param>
        private void NextKey(int Layer)
        {
            // only for lowest layer ( other layers indices are raised in NextTree() method )
            if (Layer == _numLayer - 1)
                _index[Layer]++;

            // if tree of this layer is depleted
            if (_index[Layer] == _numLeafs[Layer])
            {
                if (_numLayer != 1)
                {
                    NextTree(Layer);
                    _index[Layer] = 0;
                }
            }
            else
            {
                UpdateKey(Layer);
            }
        }

        /// <summary>
        /// Switch to next subtree if the current one is depleted
        /// </summary>
        /// 
        /// <param name="Layer">The layer the layer where the next tree is processed</param>
        private void NextTree(int Layer)
        {
            // dont create next tree for the top layer
            if (Layer > 0)
            {
                // raise index for upper layer
                _index[Layer - 1]++;

                // test if it is already the last tree
                bool lastTree = true;
                int z = Layer;
                do
                {
                    z--;
                    if (_index[z] < _numLeafs[z])
                        lastTree = false;
                }
                while (lastTree && (z > 0));

                // only construct next subtree if last one is not already in use
                if (!lastTree)
                {
                    _gmssRandom.NextSeed(_currentSeeds[Layer]);
                    // last step of distributed signature calculation
                    _nextRootSig[Layer - 1].UpdateSign();

                    // last step of distributed leaf calculation for nextNextLeaf
                    if (Layer > 1)
                        _nextNextLeaf[Layer - 1 - 1] = _nextNextLeaf[Layer - 1 - 1].NextLeaf();

                    // last step of distributed leaf calculation for upper leaf
                    _upperLeaf[Layer - 1] = _upperLeaf[Layer - 1].NextLeaf();

                    // last step of distributed leaf calculation for all treehashs
                    if (_minTreehash[Layer - 1] >= 0)
                    {
                        _upperTreehashLeaf[Layer - 1] = _upperTreehashLeaf[Layer - 1].NextLeaf();
                        byte[] leaf = _upperTreehashLeaf[Layer - 1].GetLeaf();
                        // if update is required use the precomputed leaf to update treehash
                        try
                        {
                            _currentTreehash[Layer - 1][_minTreehash[Layer - 1]].Update(_gmssRandom, leaf);
                        }
                        catch
                        {
                        }
                    }

                    // last step of nextNextAuthRoot calculation
                    UpdateNextNextAuthRoot(Layer);
                    // NOW: advance to next tree on layer 'layer' NextRootSig --> currentRootSigs
                    _currentRootSig[Layer - 1] = _nextRootSig[Layer - 1].GetSig();

                    for (int i = 0; i < _heightOfTrees[Layer] - m_K[Layer]; i++)
                    {
                        _currentTreehash[Layer][i] = _nextTreehash[Layer - 1][i];
                        _nextTreehash[Layer - 1][i] = _nextNextRoot[Layer - 1].GetTreehash()[i];
                    }

                    for (int i = 0; i < _heightOfTrees[Layer]; i++)
                    {
                        Array.Copy(_nextAuthPaths[Layer - 1][i], 0, _currentAuthPaths[Layer][i], 0, _mdLength);
                        Array.Copy(_nextNextRoot[Layer - 1].GetAuthPath()[i], 0, _nextAuthPaths[Layer - 1][i], 0, _mdLength);
                    }

                    for (int i = 0; i < m_K[Layer] - 1; i++)
                    {
                        _currentRetain[Layer][i] = _nextRetain[Layer - 1][i];
                        _nextRetain[Layer - 1][i] = _nextNextRoot[Layer - 1].GetRetain()[i];
                    }

                    _currentStack[Layer] = _nextStack[Layer - 1];
                    _nextStack[Layer - 1] = _nextNextRoot[Layer - 1].GetStack();
                    _nextRoot[Layer - 1] = _nextNextRoot[Layer - 1].GetRoot();
                    byte[] OTSseed = new byte[_mdLength];
                    byte[] dummy = new byte[_mdLength];
                    Array.Copy(_currentSeeds[Layer - 1], 0, dummy, 0, _mdLength);
                    OTSseed = _gmssRandom.NextSeed(dummy); // only need OTSSeed
                    OTSseed = _gmssRandom.NextSeed(dummy);
                    OTSseed = _gmssRandom.NextSeed(dummy);
                    _nextRootSig[Layer - 1].InitSign(OTSseed, _nextRoot[Layer - 1]);
                    // nextKey for upper layer
                    NextKey(Layer - 1);
                }
            }
        }

        internal byte[] SubtreeRootSig(int Index)
        {
            return _currentRootSig[Index];
        }

        /// <summary>
        /// This method computes the authpath (AUTH) for the current tree.
        /// Additionally the root signature for the next tree (SIG+), the authpath
        /// (AUTH++) and root (ROOT++) for the tree after next in layer
        /// <c>layer</c>, and the LEAF++^1 for the next next tree in the
        /// layer above are updated This method is used by nextKey()
        /// </summary>
        /// 
        /// <param name="Layer"></param>
        private void UpdateKey(int Layer)
        {
            // current tree processing of actual layer //
            // compute upcoming authpath for current Tree (AUTH)
            ComputeAuthPaths(Layer);

            // distributed calculations part //
            // not for highest tree layer
            if (Layer > 0)
            {
                // compute (partial) next leaf on TREE++ (not on layer 1 and 0)
                if (Layer > 1)
                    _nextNextLeaf[Layer - 1 - 1] = _nextNextLeaf[Layer - 1 - 1].NextLeaf();

                // compute (partial) next leaf on tree above (not on layer 0)
                _upperLeaf[Layer - 1] = _upperLeaf[Layer - 1].NextLeaf();
                // compute (partial) next leaf for all treehashs on tree above (not on layer 0)
                int t = (int)Math.Floor((double)(GetNumLeafs(Layer) * 2) / (double)(_heightOfTrees[Layer - 1] - m_K[Layer - 1]));

                if (_index[Layer] % t == 1)
                {
                    // take precomputed node for treehash update
                    if (_index[Layer] > 1 && _minTreehash[Layer - 1] >= 0)
                    {
                        byte[] leaf = _upperTreehashLeaf[Layer - 1].GetLeaf();
                        // if update is required use the precomputed leaf to update treehash
                        try
                        {
                            _currentTreehash[Layer - 1][_minTreehash[Layer - 1]].Update(_gmssRandom, leaf);
                        }
                        catch
                        {
                        }
                    }

                    // initialize next leaf precomputation //
                    // get lowest index of treehashs
                    _minTreehash[Layer - 1] = GetMinTreehashIndex(Layer - 1);

                    if (_minTreehash[Layer - 1] >= 0)
                    {
                        // initialize leaf
                        byte[] seed = _currentTreehash[Layer - 1][_minTreehash[Layer - 1]].GetSeedActive();
                        _upperTreehashLeaf[Layer - 1] = new GMSSLeaf(GetDigest(_msgDigestType), _otsIndex[Layer - 1], t, seed);
                        _upperTreehashLeaf[Layer - 1] = _upperTreehashLeaf[Layer - 1].NextLeaf();
                    }

                }
                else
                {
                    // update the upper leaf for the treehash one step
                    if (_minTreehash[Layer - 1] >= 0)
                        _upperTreehashLeaf[Layer - 1] = _upperTreehashLeaf[Layer - 1].NextLeaf();
                }

                // compute (partial) the signature of ROOT+ (RootSig+) (not on top layer)
                _nextRootSig[Layer - 1].UpdateSign();
                // compute (partial) AUTHPATH++ & ROOT++ (not on top layer)
                // init root and authpath calculation for tree after next (AUTH++, ROOT++)
                if (_index[Layer] == 1)
                    _nextNextRoot[Layer - 1].Initialize(new List<byte[]>());

                // update root and authpath calculation for tree after next (AUTH++, ROOT++)
                UpdateNextNextAuthRoot(Layer);
            }
        }

        /// <summary>
        /// Updates the authentication path and root calculation for the tree after next (AUTH++, ROOT++) in layer <c>layer</c>
        /// </summary>
        /// 
        /// <param name="Layer">The layer</param>
        private void UpdateNextNextAuthRoot(int Layer)
        {

            byte[] OTSseed = new byte[_mdLength];
            OTSseed = _gmssRandom.NextSeed(_nextNextSeeds[Layer - 1]);

            // get the necessary leaf
            if (Layer == _numLayer - 1)
            {
                // lowest layer computes the necessary leaf completely at this time
                WinternitzOTSignature ots = new WinternitzOTSignature(OTSseed, GetDigest(_msgDigestType), _otsIndex[Layer]);
                _nextNextRoot[Layer - 1].Update(_nextNextSeeds[Layer - 1], ots.GetPublicKey());
            }
            else
            {
                // other layers use the precomputed leafs in nextNextLeaf
                _nextNextRoot[Layer - 1].Update(_nextNextSeeds[Layer - 1], _nextNextLeaf[Layer - 1].GetLeaf());
                _nextNextLeaf[Layer - 1].InitLeafCalc(_nextNextSeeds[Layer - 1]);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is GMSSPrivateKey))
                return false;

            GMSSPrivateKey other = (GMSSPrivateKey)Obj;

            if (_currentSeeds != null && _currentSeeds.Length > 0)
                if (!Compare.IsEqual(ArrayUtils.ToBytes(_currentSeeds), ArrayUtils.ToBytes(other._currentSeeds)))
                    return false;
            if (_currentAuthPaths != null && _currentAuthPaths.Length > 0)
                if (!Compare.IsEqual(ArrayUtils.ToBytes(_currentAuthPaths), ArrayUtils.ToBytes(other._currentAuthPaths)))
                    return false;
            if (_keep != null && _keep.Length > 0)
                if (!Compare.IsEqual(ArrayUtils.ToBytes(_keep), ArrayUtils.ToBytes(other._keep)))
                    return false;

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = ArrayUtils.GetHashCode(_index);
            hash += ArrayUtils.GetHashCode(_currentSeeds);
            hash += ArrayUtils.GetHashCode(_currentAuthPaths);
            hash += ArrayUtils.GetHashCode(_keep);

            return hash;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>MPKCPublicKey copy</returns>
        public object Clone()
        {
            return new GMSSPrivateKey();
        }

        /// <summary>
        /// Create a deep copy of this GMSSPrivateKey instance
        /// </summary>
        /// 
        /// <returns>The GMSSPrivateKey copy</returns>
        public object DeepCopy()
        {
            return new GMSSPrivateKey(ToStream());
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
                    if (_index != null)
                    {
                        Array.Clear(_index, 0, _index.Length);
                        _index = null;
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
                    if (_currentAuthPaths != null)
                    {
                        Array.Clear(_currentAuthPaths, 0, _currentAuthPaths.Length);
                        _currentAuthPaths = null;
                    }
                    if (_nextAuthPaths != null)
                    {
                        Array.Clear(_nextAuthPaths, 0, _nextAuthPaths.Length);
                        _nextAuthPaths = null;
                    }
                    if (_currentTreehash != null)
                    {
                        for (int i = 0; i < _currentTreehash.Length; i++)
                        {
                            for (int j = 0; j < _currentTreehash[i].Length; j++)
                                _currentTreehash[i][j].Dispose();
                        }
                        _nextAuthPaths = null;
                    }
                    if (_nextTreehash != null)
                    {
                        for (int i = 0; i < _nextTreehash.Length; i++)
                        {
                            for (int j = 0; j < _nextTreehash[i].Length; j++)
                                _nextTreehash[i][j].Dispose();
                        }
                        _nextAuthPaths = null;
                    }
                    if (_currentStack != null)
                    {
                        Array.Clear(_currentStack, 0, _currentStack.Length);
                        _currentStack = null;
                    }
                    if (_nextStack != null)
                    {
                        Array.Clear(_nextStack, 0, _nextStack.Length);
                        _nextStack = null;
                    }
                    if (_currentRetain != null)
                    {
                        Array.Clear(_currentRetain, 0, _currentRetain.Length);
                        _currentRetain = null;
                    }
                    if (_nextRetain != null)
                    {
                        Array.Clear(_nextRetain, 0, _nextRetain.Length);
                        _nextRetain = null;
                    }
                    if (_keep != null)
                    {
                        Array.Clear(_keep, 0, _keep.Length);
                        _keep = null;
                    }
                    if (_nextNextLeaf != null)
                    {
                        for (int i = 0; i < _nextNextLeaf.Length; i++)
                            _nextNextLeaf[i].Dispose();
                        _nextNextLeaf = null;
                    }
                    if (_upperLeaf != null)
                    {
                        for (int i = 0; i < _upperLeaf.Length; i++)
                            _upperLeaf[i].Dispose();
                        _upperLeaf = null;
                    }
                    if (_upperTreehashLeaf != null)
                    {
                        for (int i = 0; i < _upperTreehashLeaf.Length; i++)
                            _upperTreehashLeaf[i].Dispose();
                        _upperTreehashLeaf = null;
                    }
                    if (_minTreehash != null)
                    {
                        Array.Clear(_minTreehash, 0, _minTreehash.Length);
                        _minTreehash = null;
                    }
                    if (_gmssPS != null)
                    {
                        _gmssPS.Dispose();
                        _gmssPS = null;
                    }
                    if (_nextRoot != null)
                    {
                        Array.Clear(_nextRoot, 0, _nextRoot.Length);
                        _nextRoot = null;
                    }
                    if (_nextNextRoot != null)
                    {
                        for (int i = 0; i < _nextNextRoot.Length; i++)
                            _nextNextRoot[i].Dispose();
                        _nextNextRoot = null;
                    }
                    if (_currentRootSig != null)
                    {
                        Array.Clear(_currentRootSig, 0, _currentRootSig.Length);
                        _currentRootSig = null;
                    }
                    if (_nextRootSig != null)
                    {
                        for (int i = 0; i < _nextRootSig.Length; i++)
                            _nextRootSig[i].Dispose();
                        _nextRootSig = null;
                    }
                    if (_heightOfTrees != null)
                    {
                        Array.Clear(_heightOfTrees, 0, _heightOfTrees.Length);
                        _heightOfTrees = null;
                    }
                    if (_otsIndex != null)
                    {
                        Array.Clear(_otsIndex, 0, _otsIndex.Length);
                        _otsIndex = null;
                    }
                    if (m_K != null)
                    {
                        Array.Clear(m_K, 0, m_K.Length);
                        m_K = null;
                    }
                    if (_numLeafs != null)
                    {
                        Array.Clear(_numLeafs, 0, _numLeafs.Length);
                        _numLeafs = null;
                    }
                    if (_msgDigestTrees != null)
                    {
                        _msgDigestTrees.Dispose();
                        _msgDigestTrees = null;
                    }
                    if (_gmssRandom != null)
                    {
                        _gmssRandom.Dispose();
                        _gmssRandom = null;
                    }
                    _mdLength = 0;
                    _numLayer = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
