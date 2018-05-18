#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    /// <summary>
    /// The VolumeKey structure. 
    /// <para>This structure is used for the encryption of a series of files, each with unique key/iv pairings; like a directory or online volume.
    /// Keys can be added, removed, and a <see cref="KeyParams"/> class containing the key material for a specific file can be returned from a key file with this 
    /// structures static methods either by index, or by using a unique file id, (like the hash value of a files full path).</para>
    /// <para>The <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.KeyFactory"/> class can be used to populate a VolumeKey structure with random keying material.
    /// This structure can be used in conjunction with the <see cref="VolumeCipher"/> class for implementing file system level disk encryption.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of creating a new <c>VolumeKey</c> structure:</description>
    /// <code>
    /// // specify key tag, key length, iv length, and number of key sets
    /// VolumeKey _keyVol = new VolumeKey(tag, 32, 16, 100);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct VolumeKey
    {
        #region Constants
        private const int TAG_SIZE = 16;
        private const int DESC_SIZE = 11;
        private const int COUNT_SIZE = 4;
        private const int ID_SIZE = 4;
        private const int STATE_SIZE = 1;
        private const int TAG_SEEK = 0;
        private const int COUNT_SEEK = TAG_SIZE + DESC_SIZE;
        private const int ID_SEEK = TAG_SIZE + DESC_SIZE + COUNT_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The volume tag; a 32 byte field identifying this volume
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = TAG_SIZE)]
        public byte[] Tag;
        /// <summary>
        /// The session key containing the cipher description
        /// </summary>
        public CipherDescription Description;
        /// <summary>
        /// The number of key/vector pairs in this container
        /// </summary>
        public int Count;
        /// <summary>
        /// The unique id array identifying each file in a set
        /// </summary>
        public int[] FileId;
        /// <summary>
        /// The current state of the file associated with a key
        /// </summary>
        public byte[] State;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize an empty VolumeKey structure; generates a random key tag identifier
        /// </summary>
        /// 
        /// <param name="Description">The cipher description</param>
        /// <param name="Count">The number of key/vector pairs</param>
        public VolumeKey(CipherDescription Description, int Count)
        {
            this.Description = Description;
            this.Count = Count;
            this.FileId = new int[Count];
            this.State = new byte[Count];
            this.Tag = new CSPPrng().GetBytes(TAG_SIZE);
            int id = 0;

            using (CSPPrng rng = new CSPPrng())
            {
                this.Tag = rng.GetBytes(TAG_SIZE);
                id = rng.Next();
            }

            for (int i = 0; i < Count; ++i)
            {
                this.State[i] = (byte)VolumeKeyStates.Unassigned;
                this.FileId[i] = id + i;
            }
        }

        /// <summary>
        /// Initialize an empty VolumeKey structure
        /// </summary>
        /// 
        /// <param name="Tag">The volume tag; a 32 byte field identifying this volume</param>
        /// <param name="Description">The cipher description</param>
        /// <param name="Count">The number of key/vector pairs</param>
        public VolumeKey(byte[] Tag, CipherDescription Description, int Count)
        {
            this.Tag = new byte[TAG_SIZE];
            Array.Copy(Tag, this.Tag, Math.Min(Tag.Length, TAG_SIZE));
            this.Description = Description;
            this.Count = Count;
            this.FileId = new int[Count];
            this.State = new byte[Count];
            int id = new CSPPrng().Next();

            for (int i = 0; i < Count; ++i)
            {
                this.State[i] = (byte)VolumeKeyStates.Unassigned;
                this.FileId[i] = id + i;
            }
        }

        
        /// <summary>
        /// Initialize the VolumeKey structure using a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The Stream containing the VolumeKey</param>
        public VolumeKey(Stream KeyStream)
        {
            KeyStream.Seek(0, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(KeyStream);

            Tag = reader.ReadBytes(TAG_SIZE);
            Description = new CipherDescription(KeyStream);
            Count = reader.ReadInt32();
            FileId = new int[Count];

            for (int i = 0; i < Count; i++)
                FileId[i] = reader.ReadInt32();

            State = reader.ReadBytes(Count);
        }

        /// <summary>
        /// Initialize the VolumeKey structure using a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the VolumeKey</param>
        public VolumeKey(byte[] KeyArray) :
            this (new MemoryStream(KeyArray))
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the size of this header
        /// </summary>
        /// 
        /// <returns>Returns the size of current structure in bytes</returns>
        public int GetHeaderSize()
        {
            return ID_SEEK + (Count * (ID_SIZE + STATE_SIZE));
        }

        /// <summary>
        /// Test if the VolumeKey contains a file id
        /// </summary>
        /// 
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>Returns true if the file id is known, otherwizse false</returns>
        public bool Contains(int Id)
        {
            for (int i = 0; i < Count; i++)
            {
                if (FileId[i] == Id)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Creates a deep copy of the key
        /// </summary>
        /// 
        /// <returns>The VolumeKey copy</returns>
        public VolumeKey DeepCopy()
        {
            return new VolumeKey(ToBytes());
        }

        /// <summary>
        /// Get the index of the file id in the VolumeKey
        /// </summary>
        /// 
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>Returns the index, or <c>-1</c> if not found</returns>
        public int GetIndex(int Id)
        {
            int index = -1;

            for (int i = 0; i < Count; i++)
            {
                if (FileId[i] == Id)
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Returns the number of keys in the volume with the specified state value
        /// </summary>
        /// 
        /// <param name="KeyState">The state to search</param>
        /// 
        /// <returns>The number of keys with that state</returns>
        public int KeyCount(VolumeKeyStates KeyState = VolumeKeyStates.Unassigned)
        {
            int count = 0;
            for (int i = 0; i < Count; i++)
            {
                if (State[i] == (byte)KeyState)
                    count++;
            }

            return count;
        }

        /// <summary>
        /// Get the next unused key/iv in the volume key
        /// </summary>
        /// 
        /// <returns>The index of the next available key pair</returns>
        public int NextSubKey()
        {
            int index = -1;
            for (int i = 0; i < Count; i++)
            {
                if (State[i] == (byte)VolumeKeyStates.Unassigned)
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            if (Tag != null)
                Array.Clear(Tag, 0, Tag.Length);
            if (FileId != null)
                Array.Clear(FileId, 0, FileId.Length);
            if (State != null)
                Array.Clear(State, 0, State.Length);

            Description.Reset();
        }

        /// <summary>
        /// Convert the VolumeKey structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the VolumeKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the VolumeKey structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the VolumeKey</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Tag);
            writer.Write(Description.ToBytes());
            writer.Write(Count);

            for (int i = 0; i < Count; i++)
                writer.Write(FileId[i]);

            writer.Write(State, 0, State.Length);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Add a new file id, and key/iv pair to the VolumeKey
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Key">The key</param>
        /// <param name="Iv">The vector</param>
        /// 
        /// <returns>Returns true if the file id is known, otherwizse false</returns>
        public static void Add(Stream KeyStream, byte[] Key, byte[] Iv)
        {
            using (MemoryStream keyMem = new MemoryStream())
            {
                // get the header
                VolumeKey vkey = new VolumeKey(KeyStream);
                int offset = ID_SEEK + (vkey.Count * ID_SIZE);
                KeyStream.Seek(offset, SeekOrigin.Begin);
                int kmlen = vkey.Count * (vkey.Description.KeySize + vkey.Description.IvSize);

                // adjust the header params
                vkey.Count++;
                ArrayUtils.AddAt(ref vkey.FileId, vkey.FileId[vkey.FileId.Length - 1]++, vkey.Count);
                ArrayUtils.AddAt(ref vkey.State, (byte)0, vkey.Count);
                // copy header to mem
                vkey.ToStream().WriteTo(keyMem);

                byte[] data = new byte[kmlen];
                // copy existing key/iv pairs
                KeyStream.Read(data, 0, data.Length);
                keyMem.Write(data, 0, data.Length);
                // write new
                keyMem.Write(Key, 0, Key.Length);
                keyMem.Write(Iv, 0, Iv.Length);

                // overwrite stream w/ new
                KeyStream.Seek(0, SeekOrigin.Begin);
                keyMem.WriteTo(KeyStream);
            }
        }

        /// <summary>
        /// Get the key/iv at a given index
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Index">The index value</param>
        /// 
        /// <returns>A populated KeyParams class</returns>
        public static KeyParams AtIndex(Stream KeyStream, int Index)
        {
            // get the header
            VolumeKey vkey = new VolumeKey(KeyStream);

            byte[] key = new byte[vkey.Description.KeySize];
            byte[] iv = new byte[vkey.Description.IvSize];
            int offset = ID_SEEK + (vkey.Count * (ID_SIZE + STATE_SIZE) + (Index * (vkey.Description.IvSize + vkey.Description.KeySize)));

            KeyStream.Seek(offset, SeekOrigin.Begin);
            KeyStream.Read(key, 0, key.Length);
            KeyStream.Read(iv, 0, iv.Length);

            return new KeyParams(key, iv);
        }

        /// <summary>
        /// Test if the VolumeKey contains a file id
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>Returns true if the file id is known, otherwizse false</returns>
        public static bool Contains(Stream KeyStream, int Id)
        {
            // get the header
            VolumeKey vkey = new VolumeKey(KeyStream);

            for (int i = 0; i < vkey.Count; i++)
            {
                if (vkey.FileId[i] == Id)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Get the key/iv associated with a file id
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>A populated KeyParams class, or null if the key is not found</returns>
        public static KeyParams FromId(Stream KeyStream, int Id)
        {
            // get the header
            VolumeKey vkey = new VolumeKey(KeyStream);

            for (int i = 0; i < vkey.Count; i++)
            {
                if (vkey.FileId[i] == Id)
                    return AtIndex(KeyStream, i);
            }

            return null;
        }

        /// <summary>
        /// Returns the number of keys in the volume with the specified state value
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="KeyState">The state to search</param>
        /// 
        /// <returns>The number of keys with that state</returns>
        public static int KeyCount(Stream KeyStream, VolumeKeyStates KeyState = VolumeKeyStates.Unassigned)
        {
            // get the header
            VolumeKey vkey = new VolumeKey(KeyStream);

            int count = 0;
            for (int i = 0; i < vkey.Count; i++)
            {
                if (vkey.State[i] == (byte)KeyState)
                    count++;
            }

            return count;
        }

        /// <summary>
        /// Get the index of the file id in the VolumeKey
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>Returns the index, or <c>-1</c> if not found</returns>
        public static int GetIndex(Stream KeyStream, int Id)
        {
            // get the header
            VolumeKey vkey = new VolumeKey(KeyStream);

            int index = -1;

            for (int i = 0; i < vkey.Count; i++)
            {
                if (vkey.FileId[i] == Id)
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Get the index of the next unused key/iv in the volume key
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// 
        /// <returns>The index of the next available key pair</returns>
        public static int NextSubKey(Stream KeyStream)
        {
            // get the header
            VolumeKey vkey = new VolumeKey(KeyStream);

            int index = -1;
            for (int i = 0; i < vkey.Count; i++)
            {
                if (vkey.State[i] == (byte)VolumeKeyStates.Unassigned)
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Remove a file id, and key/iv pair from the VolumeKey
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>Returns true if the file id is known, otherwizse false</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Id does not exist</exception>
        public static void Remove(Stream KeyStream, int Id)
        {
            int index = GetIndex(KeyStream, Id);
            if (index == -1)
                throw new CryptoProcessingException("VolumeKey:Remove", "The id does not exist!", new ArgumentException());

            using (MemoryStream keyMem = new MemoryStream())
            {
                // get the header
                VolumeKey vkey = new VolumeKey(KeyStream);
                int offset = ID_SEEK + (vkey.Count * (ID_SIZE + STATE_SIZE));
                KeyStream.Seek(offset, SeekOrigin.Begin);

                // adjust the count
                vkey.Count--;
                // create reduced arrays
                ArrayUtils.RemoveAt(ref vkey.FileId, index);
                ArrayUtils.RemoveAt(ref vkey.State, index);

                // get the key material
                int klen = vkey.Description.KeySize + vkey.Description.IvSize;
                int koff = klen * index;
                byte[] data = new byte[klen * vkey.Count];
                KeyStream.Read(data, 0, data.Length);
                ArrayUtils.RemoveRange(ref data, koff, koff + klen);
                keyMem.Write(data, 0, data.Length);

                // overwrite stream w/ new key
                KeyStream.Seek(0, SeekOrigin.Begin);
                keyMem.WriteTo(KeyStream);
            }
        }
        #endregion

        #region Private Methods
        private static byte[] Reduce(byte[] Seed)
        {
            int len = Seed.Length / 2;
            byte[] data = new byte[len];

            for (int i = 0; i < len; i++)
                data[i] = (byte)(Seed[i] ^ Seed[len + i]);

            return data;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * 31 * Count;
            hash += Description.GetHashCode();
            hash += ArrayUtils.GetHashCode(Tag);
            hash += ArrayUtils.GetHashCode(FileId);
            hash += ArrayUtils.GetHashCode(State);

            return hash;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (!(Obj is VolumeKey))
                return false;

            VolumeKey other = (VolumeKey)Obj;

            if (!Compare.IsEqual(Tag, other.Tag))
                return false;
            if (Description.GetHashCode() != other.Description.GetHashCode())
                return false;
            if (Count != other.Count)
                return false;
            if (!Compare.IsEqual(FileId, other.FileId))
                return false;
            if (!Compare.IsEqual(State,other.State))
                return false;

            return true;
        }

        /// <summary>
        /// Compare this object instance is equal to another
        /// </summary>
        /// 
        /// <param name="X">The first object</param>
        /// <param name="Y">The second object</param>
        /// 
        /// <returns>Equal</returns>
        public static bool operator ==(VolumeKey X, VolumeKey Y)
        {
            return X.Equals(Y);
        }

        /// <summary>
        /// Compare this object instance is not equal to another
        /// </summary>
        /// 
        /// <param name="X">The first object</param>
        /// <param name="Y">The second object</param>
        /// 
        /// <returns>Not equal</returns>
        public static bool operator !=(VolumeKey X, VolumeKey Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
}
