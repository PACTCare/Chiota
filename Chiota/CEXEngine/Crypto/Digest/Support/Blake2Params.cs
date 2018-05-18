#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest.Support
{
    /// <summary>
    /// The Blake2 parameters structure
    /// </summary> 
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct Blake2Params
    {
        #region Constants
        private const int HDR_SIZE = 36;
        #endregion

        #region Public Fields
        /// <summary>
        /// Get/Set: Digest byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s
        /// </summary>
        public byte DigestLength;

        /// <summary>
        /// Get/Set: Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)
        /// </summary>
        public byte KeyLength;

        /// <summary>
        /// Get/Set: Fanout (1 byte): an integer in [0, 255] (set to 0 if unlimited, and to 1 only in sequential mode)
        /// </summary>
        public byte FanOut;

        /// <summary>
        /// Get/Set: Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)
        /// </summary>
        public byte MaxDepth;

        /// <summary>
        /// Get/Set: Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)
        /// </summary>
        public int LeafLength;

        /// <summary>
        /// Get/Set: Node offset (8 or 6 bytes): an integer in [0, 264 −1] for BLAKE2b, and in [0, 248 −1] for BLAKE2s(set to 0 for the first, leftmost, leaf, or in sequential mode)
        /// </summary>
        public long NodeOffset;

        /// <summary>
        /// Get/Set: Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)
        /// </summary>
        public byte NodeDepth;

        /// <summary>
        /// Get/Set: Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)
        /// </summary>
        public byte InnerLength;

        /// <summary>
        /// Get/Set: The desired number of threads used to process the message (default is 4 for Blake2-BP, or 8 for Blake2-SP)
        /// </summary>
        public byte ThreadDepth;

        /// <summary>
        /// Get/Set: The second reserved byte
        /// </summary>
        public byte Reserved2;

        /// <summary>
        /// Get/Set: The third reserved ulong
        /// </summary>
        public long Reserved3;

        /// <summary>
        /// Get/Set: The fourth reserved ulong
        /// </summary>
        public long Reserved4;
        #endregion

        /// <summary>
        /// Initialize this structure with paramerters
        /// </summary>
        /// 
        /// <param name="DigestLength">Digest byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s</param>
        /// <param name="KeyLength">Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)</param>
        /// <param name="FanOut">Fanout (1 byte): an integer in [0, 255] (set to 0 if unlimited, and to 1 only in sequential mode)</param>
        /// <param name="MaxDepth">Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
        /// <param name="LeafLength">Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)</param>
        /// <param name="NodeOffset">Node offset (8 or 6 bytes): an integer in [0, 264 −1] for BLAKE2b, and in [0, 248 −1] for BLAKE2s(set to 0 for the first, leftmost, leaf, or in sequential mode)</param>
        /// <param name="NodeDepth">Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)</param>
        /// <param name="InnerLength">Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
        /// <param name="ThreadDepth">The number of threads used in parallel mode, the default is 4 for Blake2bp, and 8 for Blake2sp</param>
        public Blake2Params(byte DigestLength, byte KeyLength, byte FanOut, byte MaxDepth, int LeafLength, long NodeOffset, byte NodeDepth, byte InnerLength, byte ThreadDepth)
        {
            this.DigestLength = DigestLength;
            this.KeyLength = KeyLength;
            this.FanOut = FanOut;
            this.MaxDepth = MaxDepth;
            this.LeafLength = LeafLength;
            this.NodeOffset = NodeOffset;
            this.NodeDepth = NodeDepth;
            this.InnerLength = InnerLength;
            this.ThreadDepth = ThreadDepth;
            Reserved2 = 0;
            Reserved3 = 0;
            Reserved4 = 0;
        }

        /// <summary>
        /// Initialize the Blake2Params structure using a Stream
        /// </summary>
        /// 
        /// <param name="DescriptionStream">The Stream containing the Blake2Params</param>
        public Blake2Params(Stream DescriptionStream)
        {
            BinaryReader reader = new BinaryReader(DescriptionStream);
            DigestLength = reader.ReadByte();
            KeyLength = reader.ReadByte();
            FanOut = reader.ReadByte();
            MaxDepth = reader.ReadByte();
            LeafLength = reader.ReadInt16();
            NodeOffset = reader.ReadInt64();
            NodeDepth = reader.ReadByte();
            InnerLength = reader.ReadByte();
            ThreadDepth = reader.ReadByte();
            Reserved2 = reader.ReadByte();
            Reserved3 = reader.ReadByte();
            Reserved4 = reader.ReadByte();
        }

        /// <summary>
        /// Initialize the Blake2Params structure using a byte array
        /// </summary>
        /// 
        /// <param name="DescriptionArray">The byte array containing the Blake2Params</param>
        public Blake2Params(byte[] DescriptionArray) :
            this(new MemoryStream(DescriptionArray))
        {
        }

        /// <summary>
        /// Create a clone of this structure
        /// </summary>
        public Blake2Params Clone()
        {
            return new Blake2Params(DigestLength, KeyLength, FanOut, MaxDepth, LeafLength, NodeOffset, NodeDepth, InnerLength, ThreadDepth);
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public bool Equals(Blake2Params Obj)
        {
            if (this.GetHashCode() != Obj.GetHashCode())
                return false;

            return true;
        }

        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int result = 31 * DigestLength;

            result += 31 * KeyLength;
            result += 31 * FanOut;
            result += 31 * MaxDepth;
            result += 31 * LeafLength;
            result += 31 * (int)NodeOffset;
            result += 31 * NodeDepth;
            result += 31 * InnerLength;
            result += 31 * ThreadDepth;
            result += 31 * Reserved2;
            result += 31 * (int)Reserved3;
            result += 31 * (int)Reserved4;

            return result;
        }

        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return HDR_SIZE;
        }

        /// <summary>
        /// Set all struct members to defaults
        /// </summary>
        public void Reset()
        {
            DigestLength = 0;
            KeyLength = 0;
            FanOut = 0;
            MaxDepth = 0;
            LeafLength = 0;
            NodeOffset = 0;
            NodeDepth = 0;
            InnerLength = 0;
            ThreadDepth = 0;
            Reserved2 = 0;
            Reserved3 = 0;
            Reserved4 = 0;
        }

        /// <summary>
        /// Convert the Blake2Params structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the Blake2Params</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the Blake2Params structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the Blake2Params</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(DigestLength);
            writer.Write(KeyLength);
            writer.Write(FanOut);
            writer.Write(MaxDepth);
            writer.Write(LeafLength);
            writer.Write(NodeOffset);
            writer.Write(InnerLength);
            writer.Write(ThreadDepth);
            writer.Write(Reserved2);
            writer.Write(Reserved3);
            writer.Write(Reserved4);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
    };
}
