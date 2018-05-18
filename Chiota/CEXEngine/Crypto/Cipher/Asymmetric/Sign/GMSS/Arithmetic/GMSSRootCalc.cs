#region Directives
using System;
using System.Collections.Generic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic
{
    /// <summary>
    /// This class computes a whole Merkle tree and saves the needed values for AuthPath computation.
    /// It is used for precomputation of the root of a following tree. 
    /// After initialization, 2^H updates are required to complete the root. 
    /// Every update requires one leaf value as parameter. 
    /// While computing the root all initial values for the authentication path algorithm 
    /// (treehash, auth, retain) are stored for later use.
    /// </summary>
    internal sealed class GMSSRootCalc : IDisposable
    {
        #region Fields
        // max height of the tree
        private int _heightOfTree;
        // length of the messageDigest
        private int _mdLength;
        // the treehash instances of the tree
        private Treehash[] _treehash;
        // stores the retain nodes for authPath computation
        private List<byte[]>[] _ndeRetain;
        // finally stores the root of the tree when finished
        private byte[] _treeRoot;
        // stores the authentication path y_1(i), i = 0..H-1
        private byte[][] _authPath;
        // the value K for the authentication path computation
        private int m_K;
        // Vector element that stores the nodes on the stack
        private List<byte[]> _tailStack;
        // stores the height of all nodes laying on the tailStack
        private List<int> _heightOfNodes;
        // The hash function used for the construction of the authentication trees
        private IDigest _msgDigestTree;
        // stores the index of the current node on each height of the tree
        private int[] _ndeIndex;
        // true if instance was already initialized, false otherwise
        private bool m_isInitialized;
        // true it instance was finished
        private bool _isFinished;
        // Integer that stores the index of the next seed that has to be omitted to the treehashs
        private int _indexForNextSeed;
        // temporary integer that stores the height of the next treehash instance that gets initialized with a seed
        private int _heightOfNextSeed;
        private bool m_isDisposed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// This constructor regenerates a prior treehash object
        /// </summary>
        /// 
        /// <param name="Digest">The hash function</param>
        /// <param name="StatByte">The status bytes</param>
        /// <param name="StatInt">The  status ints</param>
        /// <param name="TreeH">The tree hash</param>
        /// <param name="NodeRet">The retained nodes</param>
        public GMSSRootCalc(IDigest Digest, byte[][] StatByte, int[] StatInt, Treehash[] TreeH, List<byte[]>[] NodeRet)
        {
            _msgDigestTree = Digest;
            // decode statInt
            _heightOfTree = StatInt[0];
            _mdLength = StatInt[1];
            m_K = StatInt[2];
            _indexForNextSeed = StatInt[3];
            _heightOfNextSeed = StatInt[4];

            if (StatInt[5] == 1)
                _isFinished = true;
            else
                _isFinished = false;
            
            if (StatInt[6] == 1)
                m_isInitialized = true;
            else
                m_isInitialized = false;

            int tailLength = StatInt[7];

            _ndeIndex = new int[_heightOfTree];
            for (int i = 0; i < _heightOfTree; i++)
                _ndeIndex[i] = StatInt[8 + i];

            _heightOfNodes = new List<int>();
            for (int i = 0; i < tailLength; i++)
                _heightOfNodes.Add(StatInt[8 + _heightOfTree + i]);

            // decode statByte
            _treeRoot = StatByte[0];

            _authPath = ArrayUtils.CreateJagged<byte[][]>(_heightOfTree, _mdLength);
            for (int i = 0; i < _heightOfTree; i++)
                _authPath[i] = StatByte[1 + i];

            _tailStack = new List<byte[]>();
            for (int i = 0; i < tailLength; i++)
                _tailStack.Add(StatByte[1 + _heightOfTree + i]);

            // decode treeH
            _treehash = GMSSUtil.Clone(TreeH);

            // decode ret
            _ndeRetain = GMSSUtil.Clone(NodeRet);
        }

        /// <summary>
        /// Inialize this class
        /// </summary>
        /// 
        /// <param name="HeightOfTree"> maximal height of the tree</param>
        /// <param name="K">The K value</param>
        /// <param name="Digest">The hash function</param>
        public GMSSRootCalc(int HeightOfTree, int K, IDigest Digest)
        {
            _heightOfTree = HeightOfTree;
            _msgDigestTree = Digest;
            _mdLength = _msgDigestTree.DigestSize;
            m_K = K;
            _ndeIndex = new int[HeightOfTree];
            _authPath = ArrayUtils.CreateJagged<byte[][]>(HeightOfTree, _mdLength);
            _treeRoot = new byte[_mdLength];
            // _treehash = new Treehash[HeightOfTree - K];
            _ndeRetain = new List<byte[]>[m_K - 1];

            for (int i = 0; i < K - 1; i++)
                _ndeRetain[i] = new List<byte[]>();
        }
                        
        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSRootCalc()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initializes the calculation of a new root
        /// </summary>
        /// 
        /// <param name="SharedStack">The stack shared by all treehash instances of this tree</param>
        public void Initialize(List<byte[]> SharedStack)
        {
            _treehash = new Treehash[_heightOfTree - m_K];
            for (int i = 0; i < _heightOfTree - m_K; i++)
                _treehash[i] = new Treehash(SharedStack, i, _msgDigestTree);

            _ndeIndex = new int[_heightOfTree];
            _authPath = ArrayUtils.CreateJagged<byte[][]>(_heightOfTree, _mdLength);
            _treeRoot = new byte[_mdLength];
            _tailStack = new List<byte[]>();
            _heightOfNodes = new List<int>();
            m_isInitialized = true;
            _isFinished = false;

            for (int i = 0; i < _heightOfTree; i++)
                _ndeIndex[i] = -1;

            _ndeRetain = new List<byte[]>[m_K - 1];
            for (int i = 0; i < m_K - 1; i++)
                _ndeRetain[i] = new List<byte[]>();

            _indexForNextSeed = 3;
            _heightOfNextSeed = 0;
        }

        /// <summary>
        /// Updates the root with one leaf and stores needed values in retain,
        /// treehash or authpath. Additionally counts the seeds used. 
        /// This method is used when performing the updates for TREE++.
        /// </summary>
        /// 
        /// <param name="Seed">The initial seed for treehash: seedNext</param>
        /// <param name="Leaf">The height of the treehash</param>
        public void Update(byte[] Seed, byte[] Leaf)
        {
            if (_heightOfNextSeed < (_heightOfTree - m_K) && _indexForNextSeed - 2 == _ndeIndex[0])
            {
                InitializeTreehashSeed(Seed, _heightOfNextSeed);
                _heightOfNextSeed++;
                _indexForNextSeed *= 2;
            }

            // now call the simple update
            Update(Leaf);
        }

        /// <summary>
        /// Updates the root with one leaf and stores the needed values in retain, treehash or authpath
        /// </summary>
        /// 
        /// <param name="Leaf">The height of the treehash</param>
        public void Update(byte[] Leaf)
        {
            if (_isFinished)
                return;
            if (!m_isInitialized)
                return;

            // a new leaf was omitted, so raise index on lowest layer
            _ndeIndex[0]++;

            // store the nodes on the lowest layer in treehash or authpath
            if (_ndeIndex[0] == 1)
            {
                Array.Copy(Leaf, 0, _authPath[0], 0, _mdLength);
            }
            else if (_ndeIndex[0] == 3)
            {
                // store in treehash only if K < H
                if (_heightOfTree > m_K)
                    _treehash[0].SetFirstNode(Leaf);
            }

            if ((_ndeIndex[0] - 3) % 2 == 0 && _ndeIndex[0] >= 3)
            {
                // store in retain if K = H
                if (_heightOfTree == m_K)
                    _ndeRetain[0].Insert(0, Leaf);
            }

            // if first update to this tree is made
            if (_ndeIndex[0] == 0)
            {
                _tailStack.Add(Leaf);
                _heightOfNodes.Add(0);
            }
            else
            {
                byte[] help = new byte[_mdLength];
                byte[] toBeHashed = new byte[_mdLength << 1];

                // store the new leaf in help
                Array.Copy(Leaf, 0, help, 0, _mdLength);
                int helpHeight = 0;
                // while top to nodes have same height
                while (_tailStack.Count > 0 && helpHeight == (_heightOfNodes[_heightOfNodes.Count - 1]))
                {
                    // help <-- hash(stack top element || help)
                    Array.Copy(_tailStack[_tailStack.Count - 1], 0, toBeHashed, 0, _mdLength);
                    _tailStack.RemoveAt(_tailStack.Count - 1);
                    _heightOfNodes.RemoveAt(_heightOfNodes.Count - 1);
                    Array.Copy(help, 0, toBeHashed, _mdLength, _mdLength);
                    _msgDigestTree.BlockUpdate(toBeHashed, 0, toBeHashed.Length);
                    help = new byte[_msgDigestTree.DigestSize];
                    _msgDigestTree.DoFinal(help, 0);
                    // the new help node is one step higher
                    helpHeight++;

                    if (helpHeight < _heightOfTree)
                    {
                        _ndeIndex[helpHeight]++;

                        // add index 1 element to initial authpath
                        if (_ndeIndex[helpHeight] == 1)
                            Array.Copy(help, 0, _authPath[helpHeight], 0, _mdLength);

                        if (helpHeight >= _heightOfTree - m_K)
                        {
                            // add help element to retain stack if it is a right node and not stored in treehash
                            if ((_ndeIndex[helpHeight] - 3) % 2 == 0 && _ndeIndex[helpHeight] >= 3)
                                _ndeRetain[helpHeight - (_heightOfTree - m_K)].Insert(0, help);
                        }
                        else
                        {
                            // if element is third in his line add it to treehash
                            if (_ndeIndex[helpHeight] == 3)
                                _treehash[helpHeight].SetFirstNode(help);
                        }
                    }
                }

                // push help element to the stack
                _tailStack.Add(help);
                _heightOfNodes.Add(helpHeight);

                // is the root calculation finished?
                if (helpHeight == _heightOfTree)
                {
                    _isFinished = true;
                    m_isInitialized = false;
                    _treeRoot = (byte[])_tailStack[_tailStack.Count - 1];
                }
            }
        }

        /// <summary>
        /// Initializes the seeds for the treehashs of the tree precomputed by this class
        /// </summary>
        /// 
        /// <param name="Seed">The initial seed for treehash: seedNext</param>
        /// <param name="Index">The height of the treehash</param>
        public void InitializeTreehashSeed(byte[] Seed, int Index)
        {
            _treehash[Index].InitializeSeed(Seed);
        }

        /// <summary>
        /// Method to check whether the instance has been initialized or not
        /// </summary>
        /// 
        /// <returns>Return true if treehash was already initialized</returns>
        public bool IsInitialized()
        {
            return m_isInitialized;
        }

        /// <summary>
        /// Method to check whether the instance has been finished or not
        /// </summary>
        /// 
        /// <returns>Return true if tree has reached its maximum height</returns>
        public bool IsFinished()
        {
            return _isFinished;
        }

        /// <summary>
        /// Returns the authentication path of the first leaf of the tree
        /// </summary>
        /// 
        /// <returns>The authentication path of the first leaf of the tree</returns>
        public byte[][] GetAuthPath()
        {
            return GMSSUtil.Clone(_authPath);
        }

        /// <summary>
        /// Returns the initial treehash instances, storing value y_3(i)
        /// </summary>
        /// 
        /// <returns>The initial treehash instances, storing value y_3(i)</returns>
        public Treehash[] GetTreehash()
        {
            return GMSSUtil.Clone(_treehash);
        }

        /// <summary>
        /// Returns the retain stacks storing all right nodes near to the root
        /// </summary>
        /// 
        /// <returns>The retain stacks storing all right nodes near to the root</returns>
        public List<byte[]>[] GetRetain()
        {
            return GMSSUtil.Clone(_ndeRetain);
        }

        /// <summary>
        /// Returns the finished root value
        /// </summary>
        /// 
        /// <returns>The finished root value</returns>
        public byte[] GetRoot()
        {
            return ArrayUtils.Clone(_treeRoot);
        }

        /// <summary>
        /// Returns the shared stack
        /// </summary>
        /// 
        /// <returns>The shared stack</returns>
        public List<byte[]> GetStack()
        {
            List<byte[]> copy = new List<byte[]>();
            for (int i = 0; i < _tailStack.Count; i++ )
                copy.Add(_tailStack[i]);

            return copy;
        }

        /// <summary>
        /// Returns the status byte array used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <returns>The status bytes</returns>
        public byte[][] GetStatByte()
        {
            int tailLength = 0;

            if (_tailStack != null)
                tailLength = _tailStack.Count;

            byte[][] statByte = ArrayUtils.CreateJagged<byte[][]>(1 + _heightOfTree + tailLength, _msgDigestTree.BlockSize);//FIXME: messDigestTree.getByteLength()
            statByte[0] = _treeRoot;

            for (int i = 0; i < _heightOfTree; i++)
                statByte[1 + i] = _authPath[i];

            for (int i = 0; i < tailLength; i++)
                statByte[1 + _heightOfTree + i] = (byte[])_tailStack[i];

            return statByte;
        }

        /// <summary>
        /// Returns the status int array used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <returns>The status ints</returns>
        public int[] GetStatInt()
        {
            int tailLength = 0;

            if (_tailStack != null)
                tailLength = _tailStack.Count;

            int[] statInt = new int[8 + _heightOfTree + tailLength];
            statInt[0] = _heightOfTree;
            statInt[1] = _mdLength;
            statInt[2] = m_K;
            statInt[3] = _indexForNextSeed;
            statInt[4] = _heightOfNextSeed;

            if (_isFinished)
                statInt[5] = 1;
            else
                statInt[5] = 0;
            
            if (m_isInitialized)
                statInt[6] = 1;
            else
                statInt[6] = 0;
            
            statInt[7] = tailLength;

            for (int i = 0; i < _heightOfTree; i++)
                statInt[8 + i] = _ndeIndex[i];
            
            for (int i = 0; i < tailLength; i++)
                statInt[8 + _heightOfTree + i] = ((int)_heightOfNodes[i]);

            return statInt;
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
                    if (_treehash != null)
                    {
                        for (int i = 0; i < _treehash.Length; i++)
                        {
                            _treehash[i].Dispose();
                            _treehash = null;
                        }
                    }
                    if (_ndeRetain != null)
                    {
                        Array.Clear(_ndeRetain, 0, _ndeRetain.Length);
                        _ndeRetain = null;
                    }
                    if (_treeRoot != null)
                    {
                        Array.Clear(_treeRoot, 0, _treeRoot.Length);
                        _treeRoot = null;
                    }
                    if (_authPath != null)
                    {
                        Array.Clear(_authPath, 0, _authPath.Length);
                        _authPath = null;
                    }
                    if (_tailStack != null)
                    {
                        _tailStack.Clear();
                        _tailStack = null;
                    }
                    if (_heightOfNodes != null)
                    {
                        _heightOfNodes.Clear();
                        _heightOfNodes = null;
                    }
                    if (_msgDigestTree != null)
                    {
                        _msgDigestTree.Dispose();
                        _msgDigestTree = null;
                    }
                    if (_ndeIndex != null)
                    {
                        Array.Clear(_ndeIndex, 0, _ndeIndex.Length);
                        _ndeIndex = null;
                    }
                    _heightOfTree = 0;
                    _mdLength = 0;
                    m_K = 0;
                    _indexForNextSeed = 0;
                    _heightOfNextSeed = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
