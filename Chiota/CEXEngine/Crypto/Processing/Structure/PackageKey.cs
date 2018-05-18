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
    #region PackageKey
    /// <summary>
    /// The PackageKey structure. 
    /// <para>Contains the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority"/> structure with identity and origin, attached policies, a description of the sub-key sets, 
    /// and the <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/> structure containing the description of the cipher.</para>
    /// <para>Used to create a key file that contains a series of Key, and optional Vector and Ikm sets. 
    /// A key set; the keying material assigned to a subkey, is valid for only one cycle of encryption, 
    /// guaranteeing that unique key material is used for every encryption cycle, but allowing for a key that can perform many
    /// encryptions while still exerting the maximum amount of security.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>PackageKey</c> structure:</description>
    /// <code>
    ///    PackageKey package = new PackageKey(
    ///        keypol,      // a KeyAuthority structure containing originating identity, the master policy flag, and authentication info
    ///        cpdesc       // CipherDescription structure containing all of the settings used by the cipher instance
    ///        10);         // number of key sets contained in this package
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct PackageKey
    {
        #region Constants
        // adjust these constants to match container sizes
        private const int POLICY_SIZE = 8;
        private const int CREATE_SIZE = 8;
        private const int KEYAUT_SIZE = 144;
        private const int DESC_SIZE = 11;
        private const int EXTKEY_SIZE = 16;
        private const int KEYCNT_SIZE = 4;
        private const int KEYPOL_SIZE = 8;
        private const int KEYID_SIZE = 16;

        private const long POLICY_SEEK = 0;
        private const long CREATE_SEEK = POLICY_SIZE;
        private const long KEYAUT_SEEK = POLICY_SIZE + CREATE_SIZE;
        private const long DESC_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE;
        private const long EXTKEY_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + DESC_SIZE;
        private const long KEYCNT_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + DESC_SIZE;
        private const long KEYPOL_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + DESC_SIZE + KEYCNT_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The master key policy flags, used to determine encryption state
        /// </summary>
        public long KeyPolicy;
        /// <summary>
        /// The creation date/time of this key in milliseconds
        /// </summary>
        public long CreatedOn;
        /// <summary>
        /// The <see cref="KeyAuthority">KeyAuthority</see> structure containing the key authorization schema.
        /// </summary>
        [MarshalAs(UnmanagedType.Struct, SizeConst = KEYAUT_SIZE)]
        public KeyAuthority Authority;
        /// <summary>
        /// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">CipherDescription</see> structure containing a complete description of the cipher instance.
        /// </summary>
        [MarshalAs(UnmanagedType.Struct, SizeConst = DESC_SIZE)]
        public CipherDescription Description;
        /// <summary>
        /// The number of Key Sets contained in this key package file.
        /// </summary>
        public int SubKeyCount;
        /// <summary>
        /// A <see cref="SubKeyPolicy">KeyPolicy</see> array that contains the policy flags for each sub key set
        /// </summary>
        public long[] SubKeyPolicy;
        /// <summary>
        /// An array of unique 16 byte fields that identify each sub key set
        /// </summary>
        public byte[][] SubKeyID;
        #endregion

        #region Constructor
        /// <summary>
        /// A PackageKey header structure. 
        /// </summary>
        /// 
        /// <param name="Authority">The <see cref="KeyAuthority">KeyAuthority</see> structure containing the key authorization schema.</param>
        /// <param name="Cipher">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">CipherDescription</see> structure containing a complete description of the cipher instance.</param>
        /// <param name="SubKeyCount">The number of Key Sets contained in this key package file.</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if an invalid ExtensionKey is used</exception>
        public PackageKey(KeyAuthority Authority, CipherDescription Cipher, int SubKeyCount)
        {
            this.KeyPolicy = Authority.KeyPolicy;
            this.Authority = Authority;
            this.Description = Cipher;
            this.SubKeyCount = SubKeyCount;
            SubKeyPolicy = new long[SubKeyCount];
            SubKeyID = new byte[SubKeyCount][];

            // generate the subkey ids and set master policy
            for (int i = 0; i < SubKeyCount; i++)
            {
                SubKeyPolicy[i] = (long)Authority.KeyPolicy;
                SubKeyID[i] = Guid.NewGuid().ToByteArray();
            }

            CreatedOn = DateTime.Now.Ticks;
        }

        /// <summary>
        /// Initialize the PackageKey structure using a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The Stream containing the PackageKey</param>
        public PackageKey(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);

            KeyPolicy = reader.ReadInt64();
            CreatedOn = reader.ReadInt64();
            Authority = new KeyAuthority(KeyStream);
            Description = new CipherDescription(KeyStream);
            SubKeyCount = reader.ReadInt32();
            SubKeyPolicy = new long[SubKeyCount];

            byte[] buffer = reader.ReadBytes(SubKeyCount * KEYPOL_SIZE);
            Buffer.BlockCopy(buffer, 0, SubKeyPolicy, 0, buffer.Length);

            buffer = reader.ReadBytes(SubKeyCount * KEYID_SIZE);
            SubKeyID = new byte[SubKeyCount][];

            for (int i = 0; i < SubKeyCount; i++)
            {
                SubKeyID[i] = new byte[KEYID_SIZE];
                Buffer.BlockCopy(buffer, i * KEYID_SIZE, SubKeyID[i], 0, KEYID_SIZE);
            }
        }

        /// <summary>
        /// Initialize the PackageKey structure using a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the PackageKey</param>
        public PackageKey(byte[] KeyArray) :
            this (new MemoryStream(KeyArray))
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Reset all members of the PackageKey structure, 
        /// including the CipherDescription and KeyAuthority structures
        /// </summary>
        public void Reset()
        {
            this.KeyPolicy = 0;
            this.CreatedOn = 0;
            this.Authority.Reset();
            this.Description.Reset();

            this.SubKeyCount = 0;

            if (this.SubKeyPolicy != null)
            {
                Array.Clear(this.SubKeyPolicy, 0, this.SubKeyPolicy.Length);
                this.SubKeyPolicy = null;
            }

            if (this.SubKeyID != null)
            {
                for (int i = 0; i < this.SubKeyID.Length; i++)
                {
                    if (this.SubKeyID[i] != null)
                    {
                        Array.Clear(this.SubKeyID[i], 0, this.SubKeyID[i].Length);
                        this.SubKeyID[i] = null;
                    }
                }
                this.SubKeyID = null;
            }
        }

        /// <summary>
        /// Convert the PackageKey structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the PackageKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the PackageKey structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the PackageKey</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(KeyPolicy);
            writer.Write(CreatedOn);
            writer.Write(Authority.ToBytes());
            writer.Write(Description.ToBytes());
            writer.Write(SubKeyCount);

            byte[] buffer = new byte[SubKeyCount * KEYPOL_SIZE];
            Buffer.BlockCopy(SubKeyPolicy, 0, buffer, 0, buffer.Length);
            writer.Write(buffer);

            buffer = new byte[SubKeyCount * KEYID_SIZE];

            for (int i = 0; i < SubKeyCount; i++)
                Buffer.BlockCopy(SubKeyID[i], 0, buffer, i * KEYID_SIZE, KEYID_SIZE);

            writer.Write(buffer);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <param name="Package">The key package structure</param>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize(PackageKey Package)
        {
            return POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + DESC_SIZE + KEYCNT_SIZE + (Package.SubKeyCount * (KEYPOL_SIZE + KEYID_SIZE));
        }

        /// <summary>
        /// Get policy flag offset
        /// </summary>
        /// 
        /// <returns>offset size</returns>
        public static int GetPolicyOffset()
        {
            return POLICY_SIZE;
        }

        /// <summary>
        /// Get the key master policy flags
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Key policy flags</returns>
        public static long GetKeyPolicy(Stream KeyStream)
        {
            KeyStream.Seek(POLICY_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt64();
        }

        /// <summary>
        /// Get the creation date/time timestamp (in milliseconds)
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Created on timestamp</returns>
        public static long GetCreatedOn(Stream KeyStream)
        {
            KeyStream.Seek(CREATE_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt64();
        }

        /// <summary>
        /// Get the KeyAuthority structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a KeyAuthority structure</param>
        /// 
        /// <returns>KeyAuthority structure</returns>
        public static KeyAuthority GetKeyAuthority(Stream KeyStream)
        {
            KeyStream.Seek(KEYAUT_SEEK, SeekOrigin.Begin);
            return new KeyAuthority(KeyStream);
        }

        /// <summary>
        /// Get the cipher description header
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>CipherDescription structure</returns>
        public static CipherDescription GetCipherDescription(Stream KeyStream)
        {
            KeyStream.Seek(DESC_SEEK, SeekOrigin.Begin);
            return new CipherDescription(KeyStream);
        }

        /// <summary>
        /// Get the number of subkey sets contained in the key package
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Number of subkey sets</returns>
        public static int GetSubKeyCount(Stream KeyStream)
        {
            KeyStream.Seek(KEYCNT_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the subkey policy flags contained in the key package
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Policy flag array</returns>
        public static long[] GetSubKeyPolicies(Stream KeyStream)
        {
            int count = GetSubKeyCount(KeyStream);
            KeyStream.Seek(KEYPOL_SEEK, SeekOrigin.Begin);
            byte[] buffer = new BinaryReader(KeyStream).ReadBytes(count * KEYPOL_SIZE);
            long[] policies = new long[count];
            Buffer.BlockCopy(buffer, 0, policies, 0, buffer.Length);

            return policies;
        }

        /// <summary>
        /// Get the subkey identity arrays
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Subkey id arrays</returns>
        public static byte[][] GetSubKeyIds(Stream KeyStream)
        {
            int skcnt = GetSubKeyCount(KeyStream);
            long idpos = KEYPOL_SEEK + (skcnt * KEYPOL_SIZE);
            KeyStream.Seek(idpos, SeekOrigin.Begin);

            byte[] buffer = new BinaryReader(KeyStream).ReadBytes(skcnt * KEYID_SIZE);
            byte[][] ids = new byte[skcnt][];

            for (int i = 0; i < skcnt; i++)
            {
                ids[i] = new byte[KEYID_SIZE];
                Buffer.BlockCopy(buffer, i * KEYID_SIZE, ids[i], 0, KEYID_SIZE);
            }

            return ids;
        }
        #endregion

        #region Setters
        /// <summary>
        /// Set the Key master policy flag
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Flags">Key policy flags</param>
        public static void SetKeyPolicy(Stream KeyStream, long Flags)
        {
            KeyStream.Seek(POLICY_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Flags);
        }

        /// <summary>
        /// Set the Key package creation time
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="TimeStamp">Creation Date/Time in milliseconds</param>
        public static void SetCreatedOn(Stream KeyStream, long TimeStamp)
        {
            KeyStream.Seek(CREATE_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(TimeStamp);
        }

        /// <summary>
        /// Set the KeyAuthority structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Authority">The CipherDescription structure</param>
        public static void SetKeyAuthority(Stream KeyStream, KeyAuthority Authority)
        {
            KeyStream.Seek(KEYAUT_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Authority.ToBytes());
        }

        /// <summary>
        /// Set the CipherDescription structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Description">The CipherDescription structure</param>
        public static void SetCipherDescription(Stream KeyStream, CipherDescription Description)
        {
            KeyStream.Seek(DESC_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Description.ToBytes());
        }

        /// <summary>
        /// Set the Key package SubKey Count
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Count">Number of SubKeys in the package</param>
        public static void SetSubKeyCount(Stream KeyStream, int Count)
        {
            KeyStream.Seek(KEYCNT_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Count);
        }

        /// <summary>
        /// Set the SubKeyId arrays
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="KeyIds">Array of SubKey Id arrays</param>
        public static void SetSubKeyIds(Stream KeyStream, byte[][] KeyIds)
        {
            int skcnt = GetSubKeyCount(KeyStream);
            byte[] buffer = new byte[skcnt * KEYID_SIZE];

            for (int i = 0; i < skcnt; i++)
                Buffer.BlockCopy(KeyIds[i], 0, buffer, i * KEYID_SIZE, KEYID_SIZE);

            long pos = KEYPOL_SEEK + (skcnt * KEYPOL_SIZE);
            KeyStream.Seek(pos, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(buffer);
        }

        /// <summary>
        /// Set the Key package SubKey Policy flags
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Policies">Array of SubKey policy flags</param>
        public static void SetSubKeyPolicies(Stream KeyStream, long[] Policies)
        {
            byte[] buffer = new byte[Policies.Length * KEYPOL_SIZE];
            Buffer.BlockCopy(Policies, 0, buffer, 0, buffer.Length);
            KeyStream.Seek(KEYPOL_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(buffer);
        }
        #endregion

        #region Key Methods
        /// <summary>
        /// Get the key/iv at a given index
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the PackageKey</param>
        /// <param name="Index">The index value</param>
        /// 
        /// <returns>A populated KeyParams class</returns>
        public static KeyParams AtIndex(Stream KeyStream, int Index)
        {
            // get the header
            PackageKey pkey = new PackageKey(KeyStream);

            byte[] key = new byte[pkey.Description.KeySize];
            byte[] iv = new byte[pkey.Description.IvSize];
            byte[] ikm = new byte[pkey.Description.MacKeySize];

            int offset = GetHeaderSize(pkey) + (Index * (pkey.Description.IvSize + pkey.Description.KeySize + pkey.Description.MacKeySize));

            KeyStream.Seek(offset, SeekOrigin.Begin);
            KeyStream.Read(key, 0, key.Length);
            KeyStream.Read(iv, 0, iv.Length);
            KeyStream.Read(ikm, 0, ikm.Length);

            return new KeyParams(key, iv, ikm);
        }

        /// <summary>
        /// Test if the PackageKey contains a file id
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the PackageKey</param>
        /// <param name="Id">The subkey id</param>
        /// 
        /// <returns>Returns true if the file id is known, otherwizse false</returns>
        public static bool Contains(Stream KeyStream, byte[] Id)
        {
            // get the header
            PackageKey pkey = new PackageKey(KeyStream);

            for (int i = 0; i < pkey.SubKeyID.Length; i++)
            {
                if (pkey.SubKeyID[i] == Id)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Get the key/iv associated with a file id
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the PackageKey</param>
        /// <param name="Id">The file id</param>
        /// 
        /// <returns>A populated KeyParams class, or null if the key is not found</returns>
        public static KeyParams FromId(Stream KeyStream, byte[] Id)
        {
            // get the header
            PackageKey vkey = new PackageKey(KeyStream);

            for (int i = 0; i < vkey.SubKeyID.Length; i++)
            {
                if (vkey.SubKeyID[i] == Id)
                    return AtIndex(KeyStream, i);
            }

            return null;
        }

        /// <summary>
        /// Find a subkey index position within the stream
        /// </summary>
        /// <param name="KeyStream">The stream containing a PackageKey structure</param>
        /// <param name="KeyId">The unique identifies of the sub key</param>
        /// 
        /// <returns>The index or -1 if the subkey was not found</returns>
        public static int IndexFromId(Stream KeyStream, byte[] KeyId)
        {
            int index = -1;
            byte[][] keyIds = GetSubKeyIds(KeyStream);

            for (int i = 0; i < keyIds.Length; i++)
            {
                if (Compare.IsEqual(keyIds[i], KeyId))
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Returns the number of keys in the package with the specified policy value
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="KeyPolicy">The key policy to search</param>
        /// 
        /// <returns>The number of keys with that policy</returns>
        public static int KeyCount(Stream KeyStream, KeyPolicies KeyPolicy)
        {
            // get the header
            PackageKey pkey = new PackageKey(KeyStream);

            int count = 0;
            for (int i = 0; i < pkey.SubKeyID.Length; i++)
            {
                if (KeyHasPolicy(pkey.SubKeyPolicy[i], (long)KeyPolicy))
                    count++;
            }

            return count;
        }

        /// <summary>
        /// Test if a specific KeyPolicy is within a policy group
        /// </summary>
        /// 
        /// <param name="PolicyGroup">Policies group as an integer</param>
        /// <param name="KeyPolicy">Policy to test for existence</param>
        /// 
        /// <returns>True if it contains the KeyPolicy</returns>
        public static bool KeyHasPolicy(long PolicyGroup, long KeyPolicy)
        {
            return ((PolicyGroup & (long)KeyPolicy) == (long)KeyPolicy);
        }

        /// <summary>
        /// Get the index of the file id in the VolumeKey
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Id">The key id</param>
        /// 
        /// <returns>Returns the index, or <c>-1</c> if not found</returns>
        public static int GetIndex(Stream KeyStream, byte[] Id)
        {
            // get the header
            PackageKey pkey = new PackageKey(KeyStream);

            int index = -1;

            for (int i = 0; i < pkey.SubKeyID.Length; i++)
            {
                if (pkey.SubKeyID[i] == Id)
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Gets the next subkey available for encryption
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Index of subkey, or -1 for empty</returns>
        public static int NextSubkey(Stream KeyStream)
        {
            int index = -1;
            long[] policies = GetSubKeyPolicies(KeyStream);

            for (int i = 0; i < policies.Length; i++)
            {
                if (!KeyHasPolicy(policies[i], (long)PackageKeyStates.Expired))
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Clear all policy flags from the KeyPolicy at the specified Index
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package, changes are written to this stream</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Indexed value does not exist</exception>
        public static void SubKeyClearPolicies(Stream KeyStream, int Index)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new CryptoProcessingException("PackageKey:SubKeyClearPolicies", "The specified index does not exist!", new ArgumentOutOfRangeException());

            expol[Index] = 0;

            SetSubKeyPolicies(KeyStream, expol);
        }

        /// <summary>
        /// Clear the KeyPolicy flag from the KeyPolicy at the specified Index
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a PackageKey, changes are written to this stream</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// <param name="KeyPolicy">KeyPolicy flag to clear</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Indexed value does not exist</exception>
        public static void SubKeyClearPolicy(Stream KeyStream, int Index, long KeyPolicy)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new CryptoProcessingException("PackageKey:SubKeyClearPolicy", "The specified index does not exist!", new ArgumentOutOfRangeException());

            if (KeyHasPolicy(expol[Index], KeyPolicy))
                expol[Index] &= ~KeyPolicy;

            SetSubKeyPolicies(KeyStream, expol);
        }

        /// <summary>
        /// Test if a specific KeyPolicy is within a policy group
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// <param name="KeyPolicy">Policy to test for existence</param>
        /// 
        /// <returns>True if it contains the KeyPolicy</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Indexed value does not exist</exception>
        public static bool SubKeyHasPolicy(Stream KeyStream, int Index, long KeyPolicy)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new CryptoProcessingException("PackageKey:SubKeyHasPolicy", "The specified index does not exist!", new ArgumentOutOfRangeException());

            return ((expol[Index] & (long)KeyPolicy) == (long)KeyPolicy);
        }

        /// <summary>
        /// Gdet the starting position of the key material (key/iv/mac key) of a specific subkey within the key package file
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="KeyId">The unique identifies of the sub key</param>
        /// 
        /// <returns>The starting position index of the key material</returns>
        public static long SubKeyOffset(Stream KeyStream, byte[] KeyId)
        {
            long keyPos = -1;
            int index = IndexFromId(KeyStream, KeyId);

            if (index == -1)
                return keyPos;

            int keyCount = GetSubKeyCount(KeyStream);
            CipherDescription cipher = GetCipherDescription(KeyStream);
            int keySize = cipher.KeySize + cipher.IvSize + cipher.MacKeySize;
            int hdrSize = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + DESC_SIZE + KEYCNT_SIZE + (keyCount * (KEYPOL_SIZE + KEYID_SIZE));
            keyPos = hdrSize + (keySize * index);

            return keyPos;
        }

        /// <summary>
        /// Set a policy flag on a member of the KeyPolicies array
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// <param name="KeyPolicy">Policy flag to add to the KeyPolicy</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Indexed value does not exist</exception>
        public static void SubKeySetPolicy(Stream KeyStream, int Index, long KeyPolicy)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new CryptoProcessingException("PackageKey:SubKeySetPolicy", "The specified index does not exist!", new ArgumentOutOfRangeException());

            if (!KeyHasPolicy(expol[Index], KeyPolicy))
            {
                expol[Index] |= KeyPolicy;
                SetSubKeyPolicies(KeyStream, expol);
            }
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
            int hash = 31 * (int)KeyPolicy;
            hash += 31 * (int)CreatedOn;
            hash += 31 * SubKeyCount;
            hash += Authority.GetHashCode();
            hash += Description.GetHashCode();
            hash += ArrayUtils.GetHashCode(SubKeyPolicy);
            hash += ArrayUtils.GetHashCode(SubKeyID);

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
            if (!(Obj is PackageKey))
                return false;

            PackageKey other = (PackageKey)Obj;

            if (KeyPolicy != other.KeyPolicy)
                return false;
            if (CreatedOn != other.CreatedOn)
                return false;
            if (Authority.GetHashCode() != other.Authority.GetHashCode())
                return false;
            if (Description.GetHashCode() != other.Description.GetHashCode())
                return false;
            if (SubKeyCount != other.SubKeyCount)
                return false;
            if (!Compare.IsEqual(SubKeyPolicy, other.SubKeyPolicy))
                return false;

            if (SubKeyID.Length != 0)
            {
                for (int i = 0; i < SubKeyID.Length; ++i)
                {
                    if (SubKeyID[i].Length != 0)
                    {
                        for (int j = 0; j < SubKeyID[i].Length; ++j)
                        {
                            if (SubKeyID[i][j] != other.SubKeyID[i][j])
                                return false;
                        }
                    }
                }
            }

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
        public static bool operator ==(PackageKey X, PackageKey Y)
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
        public static bool operator !=(PackageKey X, PackageKey Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
    #endregion
}
