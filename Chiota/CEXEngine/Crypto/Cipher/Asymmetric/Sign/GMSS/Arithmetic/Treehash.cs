#region Directives
using System;
using System.Collections.Generic;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic
{
    /// <summary>
    /// This class implements a treehash instance for the Merkle tree traversal algorithm.
    /// The first node of the stack is stored in this instance itself,
    /// additional tail nodes are stored on a tailstack.
    /// </summary>
    internal sealed class Treehash : IDisposable
    {
        #region Fields
        // max height of current treehash instance.
        private int _maxHeight;
        // Vector element that stores the nodes on the stack
        private List<byte[]> _tailStack;
        // Vector element that stores the height of the nodes on the stack
        private List<int> _heightOfNodes;
        // the first node is stored in the treehash instance itself, not on stack
        private byte[] _firstNode;
        // seedActive needed for the actual node
        private byte[] _seedActive;
        // the seed needed for the next re-initialization of the treehash instance
        private byte[] _seedNext;
        // number of nodes stored on the stack and belonging to this treehash instance
        private int _tailLength;
        // the height in the tree of the first node stored in treehash
        private int _firstNodeHeight;
        // true if treehash instance was already initialized, false otherwise
        private bool m_isInitialized;
        // true if the first node's height equals the maxHeight of the treehash
        private bool _isFinished;
        // true if the nextSeed has been initialized with index 3*2^h needed for the seed scheduling
        private bool _seedInitialized;
        // denotes the Message Digest used by the tree to create nodes
        private IDigest _msgDigestTree;
        private bool m_isDisposed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// This constructor regenerates a prior treehash object
        /// </summary>
        /// 
        /// <param name="Digest">The initialized hash function</param>
        /// <param name="StatByte">The status bytes</param>
        /// <param name="StatInt">The status ints</param>
        public Treehash(IDigest Digest, byte[][] StatByte, int[] StatInt)
        {
            _msgDigestTree = Digest;

            // decode statInt
            _maxHeight = StatInt[0];
            _tailLength = StatInt[1];
            _firstNodeHeight = StatInt[2];

            if (StatInt[3] == 1)
                _isFinished = true;
            else
                _isFinished = false;

            if (StatInt[4] == 1)
                m_isInitialized = true;
            else
                m_isInitialized = false;

            if (StatInt[5] == 1)
                _seedInitialized = true;
            else
                _seedInitialized = false;

            _heightOfNodes = new List<int>();
            for (int i = 0; i < _tailLength; i++)
                _heightOfNodes.Add(StatInt[6 + i]);

            // decode statByte
            _firstNode = StatByte[0];
            _seedActive = StatByte[1];
            _seedNext = StatByte[2];

            _tailStack = new List<byte[]>();
            for (int i = 0; i < _tailLength; i++)
                _tailStack.Add(StatByte[3 + i]);
        }

        /// <summary>
        /// This constructor regenerates a prior treehash object from an encoded stream
        /// </summary>
        /// 
        /// <param name="Digest">The initialized hash function</param>
        /// <param name="TreeStream">The stream containing the encoded TreeHash</param>
        public Treehash(IDigest Digest, Stream TreeStream)
        {
            BinaryReader reader = new BinaryReader(TreeStream);
            int len;
            byte[] data;

            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            byte[][] statByte = ArrayUtils.ToArray2x8(data);
            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            int[] statInt = ArrayUtils.ToArray32(data);
            _msgDigestTree = Digest;

            // decode statInt
            _maxHeight = statInt[0];
            _tailLength = statInt[1];
            _firstNodeHeight = statInt[2];

            if (statInt[3] == 1)
                _isFinished = true;
            else
                _isFinished = false;

            if (statInt[4] == 1)
                m_isInitialized = true;
            else
                m_isInitialized = false;

            if (statInt[5] == 1)
                _seedInitialized = true;
            else
                _seedInitialized = false;

            _heightOfNodes = new List<int>();
            for (int i = 0; i < _tailLength; i++)
                _heightOfNodes.Add(statInt[6 + i]);

            // decode statByte
            _firstNode = statByte[0];
            _seedActive = statByte[1];
            _seedNext = statByte[2];

            _tailStack = new List<byte[]>();
            for (int i = 0; i < _tailLength; i++)
                _tailStack.Add(statByte[3 + i]);
        }
        
        /// <summary>
        /// Reconstructs a Treehash from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Digest">The hash digest</param>
        /// <param name="TreeArray">The encoded tree hash</param>
        public Treehash(IDigest Digest, byte[] TreeArray) :
            this(Digest, new MemoryStream(TreeArray))
        {
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="TailStack">The vector element where the stack nodes are stored</param>
        /// <param name="MaxHeight">The maximal height of the treehash instance</param>
        /// <param name="Digest">The initialized hash function</param>
        public Treehash(List<byte[]> TailStack, int MaxHeight, IDigest Digest)
        {
            _tailStack = TailStack;
            _maxHeight = MaxHeight;
            _firstNode = null;
            m_isInitialized = false;
            _isFinished = false;
            _seedInitialized = false;
            _msgDigestTree = Digest;
            _seedNext = new byte[_msgDigestTree.DigestSize];
            _seedActive = new byte[_msgDigestTree.DigestSize];
        }
        
        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Treehash()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Destroys a treehash instance after the top node was taken for authentication path
        /// </summary>
        public void Destroy()
        {
            m_isInitialized = false;
            _isFinished = false;
            _firstNode = null;
            _tailLength = 0;
            _firstNodeHeight = -1;
        }

        /// <summary>
        /// Method to initialize the seeds needed for the precomputation of right nodes.
        /// Should be initialized with index 3*2^i for treehash_i
        /// </summary>
        /// 
        /// <param name="Seed">The seed value</param>
        public void InitializeSeed(byte[] Seed)
        {
            Array.Copy(Seed, 0, _seedNext, 0, _msgDigestTree.DigestSize);
            _seedInitialized = true;
        }

        /// <summary>
        /// Initializes the treehash instance. The seeds must already have been initialized to work correctly.
        /// </summary>
        public void Initialize()
        {
            if (!_seedInitialized)
                return;

            _heightOfNodes = new List<int>();
            _tailLength = 0;
            _firstNode = null;
            _firstNodeHeight = -1;
            m_isInitialized = true;
            Array.Copy(_seedNext, 0, _seedActive, 0, _msgDigestTree.DigestSize);
        }

        /// <summary>
        /// Returns the first node stored in treehash instance itself
        /// </summary>
        /// 
        /// <returns>Return the first node stored in treehash instance itself</returns>
        public byte[] GetFirstNode()
        {
            return _firstNode;
        }

        /// <summary>
        /// Returns the top node height
        /// </summary>
        /// 
        /// <returns>Height of the first node, the top node</returns>
        public int GetFirstNodeHeight()
        {
            if (_firstNode == null)
                return _maxHeight;
            
            return _firstNodeHeight;
        }

        /// <summary>
        /// Returns the height of the lowest node stored either in treehash or on the stack. 
        /// It must not be set to infinity (as mentioned in the paper) because this cases are 
        /// considered in the computeAuthPaths method of JDKGMSSPrivateKey
        /// </summary>
        /// 
        /// <returns>Height of the lowest node</returns>
        public int GetLowestNodeHeight()
        {
            if (_firstNode == null)
                return _maxHeight;
            else if (_tailLength == 0)
                return _firstNodeHeight;
            else
                return Math.Min(_firstNodeHeight, ((int)_heightOfNodes[_heightOfNodes.Count - 1]));
        }

        /// <summary>
        /// Returns the active seed
        /// </summary>
        /// 
        /// <returns>Return the active seed</returns>
        public byte[] GetSeedActive()
        {
            return _seedActive;
        }

        /// <summary>
        /// Returns the status byte array used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <returns>The status bytes</returns>
        public byte[][] GetStatByte()
        {

            byte[][] statByte = ArrayUtils.CreateJagged<byte[][]>(3 + _tailLength, _msgDigestTree.DigestSize);
            statByte[0] = _firstNode;
            statByte[1] = _seedActive;
            statByte[2] = _seedNext;

            for (int i = 0; i < _tailLength; i++)
                statByte[3 + i] = (byte[])_tailStack[i];
        
            return statByte;
        }

        /// <summary>
        /// Returns the status int array used by the GMSSPrivateKeyASN.1 class
        /// </summary>
        /// 
        /// <returns>The status ints</returns>
        public int[] GetStatInt()
        {

            int[] statInt = new int[6 + _tailLength];
            statInt[0] = _maxHeight;
            statInt[1] = _tailLength;
            statInt[2] = _firstNodeHeight;
            if (_isFinished)
                statInt[3] = 1;
            else
                statInt[3] = 0;

            if (m_isInitialized)
                statInt[4] = 1;
            else
                statInt[4] = 0;
            
            if (_seedInitialized)
                statInt[5] = 1;
            else
                statInt[5] = 0;
            
            for (int i = 0; i < _tailLength; i++)
                statInt[6 + i] = _heightOfNodes[i];
            
            return statInt;
        }

        /// <summary>
        /// Returns the tailstack
        /// </summary>
        /// 
        /// <returns>Return the tailstack</returns>
        public List<byte[]> GetTailStack()
        {
            return _tailStack;
        }

        /// <summary>
        /// Method to check whether the instance has been finished or not
        /// </summary>
        /// 
        /// <returns>Return true if treehash has reached its maximum height</returns>
        public bool IsFinished()
        {
            return _isFinished;
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
        /// This method sets the first node stored in the treehash instance itself
        /// </summary>
        /// 
        /// <param name="Hash">The hash value</param>
        public void SetFirstNode(byte[] Hash)
        {
            if (!m_isInitialized)
                Initialize();
            
            _firstNode = Hash;
            _firstNodeHeight = _maxHeight;
            _isFinished = true;
        }

        /// <summary>
        /// Converts the Treehash to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded Treehash</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the Treehash to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Treehash encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] data;

            data = ArrayUtils.ToBytes(GetStatByte());
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(GetStatInt());
            writer.Write(data.Length);
            writer.Write(data);
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Calculates one update of the treehash instance, i.e. creates a new leaf and hashes if possible
        /// </summary>
        /// 
        /// <param name="GmssRand">An instance of the PRNG</param>
        /// <param name="Leaf">The byte value of the leaf needed for the update</param>
        public void Update(GMSSRandom GmssRand, byte[] Leaf)
        {
            if (_isFinished)
                return;
            if (!m_isInitialized)
                return;

            byte[] help = new byte[_msgDigestTree.DigestSize];
            int helpHeight = -1;

            GmssRand.NextSeed(_seedActive);

            // if treehash gets first update
            if (_firstNode == null)
            {
                _firstNode = Leaf;
                _firstNodeHeight = 0;
            }
            else
            {
                // store the new node in help array, do not push it on the stack
                help = Leaf;
                helpHeight = 0;

                // hash the nodes on the stack if possible
                while (_tailLength > 0 && helpHeight == ((int)_heightOfNodes[_heightOfNodes.Count - 1]))
                {
                    // put top element of the stack and help node in array 'tobehashed'
                    // and hash them together, put result again in help array
                    byte[] toBeHashed = new byte[_msgDigestTree.DigestSize << 1];

                    // pop element from stack
                    Array.Copy(_tailStack[_tailStack.Count - 1], 0, toBeHashed, 0, _msgDigestTree.DigestSize);
                    _tailStack.RemoveAt(_tailStack.Count - 1);
                    _heightOfNodes.RemoveAt(_heightOfNodes.Count - 1);

                    Array.Copy(help, 0, toBeHashed, _msgDigestTree.DigestSize, _msgDigestTree.DigestSize);
                    _msgDigestTree.BlockUpdate(toBeHashed, 0, toBeHashed.Length);
                    help = new byte[_msgDigestTree.DigestSize];
                    _msgDigestTree.DoFinal(help, 0);

                    // increase help height, stack was reduced by one element
                    helpHeight++;
                    _tailLength--;
                }

                // push the new node on the stack
                _tailStack.Add(help);
                _heightOfNodes.Add(helpHeight);
                _tailLength++;

                // finally check whether the top node on stack and the first node in treehash have same height. 
                // If so hash them together and store them in treehash
                if (((int)_heightOfNodes[_heightOfNodes.Count - 1] == _firstNodeHeight))
                {
                    byte[] toBeHashed = new byte[_msgDigestTree.DigestSize << 1];
                    Array.Copy(_firstNode, 0, toBeHashed, 0, _msgDigestTree.DigestSize);
                    // pop element from tailStack and copy it into help2 array
                    Array.Copy(_tailStack[_tailStack.Count - 1], 0, toBeHashed, _msgDigestTree.DigestSize, _msgDigestTree.DigestSize);
                    _tailStack.RemoveAt(_tailStack.Count - 1);
                    _heightOfNodes.RemoveAt(_heightOfNodes.Count - 1);
                    // store new element in firstNode, stack is then empty
                    _msgDigestTree.BlockUpdate(toBeHashed, 0, toBeHashed.Length);
                    _firstNode = new byte[_msgDigestTree.DigestSize];
                    _msgDigestTree.DoFinal(_firstNode, 0);
                    _firstNodeHeight++;
                    // empty the stack
                    _tailLength = 0;
                }
            }

            // check if treehash instance is completed
            if (_firstNodeHeight == _maxHeight)
                _isFinished = true;
        }

        /// <summary>
        /// Updates the nextSeed of this treehash instance one step needed for the schedulng of the seeds
        /// </summary>
        /// 
        /// <param name="GmssRand">The prng used for the seeds</param>
        public void UpdateNextSeed(GMSSRandom GmssRand)
        {
            GmssRand.NextSeed(_seedNext);
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
                    if (_firstNode != null)
                    {
                        Array.Clear(_firstNode, 0, _firstNode.Length);
                        _firstNode = null;
                    }
                    if (_seedActive != null)
                    {
                        Array.Clear(_seedActive, 0, _seedActive.Length);
                        _seedActive = null;
                    }
                    if (_seedNext != null)
                    {
                        Array.Clear(_seedNext, 0, _seedNext.Length);
                        _seedNext = null;
                    }
                    if (_msgDigestTree != null)
                    {
                        _msgDigestTree.Dispose();
                        _msgDigestTree = null;
                    }
                    _maxHeight = 0;
                    _tailLength = 0;
                    _firstNodeHeight = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
