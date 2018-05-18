#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Utility;

#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    #region Key Authority
    /// <summary>
    /// The KeyAuthority structure.
    /// <para>Contains origin information, authentication controls data, and policy flags that determine how a <see cref="PackageKey"/> is processed.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of defining a KeyAuthority structure:</description>
    /// <code>
    /// // populate the KeyAuthority structure; used for key identity, post creation control, and layered authorization.
    /// // see the PolicyFlags enumeration and KeyAuthority class for more information
    /// KeyAuthority keyAuth = new KeyAuthority(
    ///    _domainId,                      // can be a domain path, a shared secret, or a target identity
    ///    _originId,                      // the unique id of the creator of this key package
    ///    _pkgId,                         // can uniquely identify the software that created this key package, or the package itself
    ///    _pkgTag,                        // can be a friendly name, storage for a layered authentication scheme, or details about this package or provider
    ///    KeyPolicies.NoNarrative |       // policy flag; the target of this key has limited knowledge about the keys construction and origin
    ///    KeyPolicies.PostOverwrite);     // policy flag; each package subkey can be read only once for decryption, after which it is overwritten in the key package file
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>The <see cref="KeyAuthority.DomainId"/> 32 byte field can be used to authenticate a domain when used with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/> DomainAuth policy flag.</description></item>
    /// <item><description>The <see cref="KeyAuthority.OriginId"/> is used to identify the creator of the key and is unique to each installation. This id can be used as a secret id in a trust relationship.</description></item>
    /// <item><description>A <see cref="KeyAuthority.PackageId"/> 32 byte field can be used as a software id, or as an authentication string if using the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies.PackageAuth"/> policy flag.</description></item>
    /// <item><description>A <see cref="KeyAuthority.PackageTag"/> field is a 32 byte description field that can contain a package or creator description string.</description></item>
    /// <item><description>The <see cref="KeyAuthority.KeyPolicy"/> is a master flag; all subkeys in this package will use the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/> defined by this flag.</description></item>
    /// <item><description>The <see cref="KeyAuthority.OptionFlag"/> when used with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies.Volatile"/> policy flag, stores the date/time in Ticks, after which this key must be expired or destroyed.</description></item>
    /// </list>
    /// </remarks>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct KeyAuthority
    {
        #region Constants
        // id constants can be changed to adjust field size
        private const int DOMAINID_SIZE = 32;
        private const int ORIGINID_SIZE = 16;
        private const int TARGETID_SIZE = 16;
        private const int PACKGID_SIZE = 32;
        private const int PACKGTAG_SIZE = 32;
        private const int KEYPOL_SIZE = 8;
        private const int OPTFLG_SIZE = 8;
        private const int AUTHDR_SIZE = DOMAINID_SIZE + ORIGINID_SIZE + TARGETID_SIZE + PACKGID_SIZE + PACKGTAG_SIZE + KEYPOL_SIZE + OPTFLG_SIZE;

        private const long DOMAINID_SEEK = 0;
        private const long ORIGINID_SEEK = DOMAINID_SIZE;
        private const long TARGETID_SEEK = DOMAINID_SIZE + ORIGINID_SIZE;
        private const long PACKGEID_SEEK = DOMAINID_SIZE + ORIGINID_SIZE + TARGETID_SEEK;
        private const long PACKGTAG_SEEK = DOMAINID_SIZE + ORIGINID_SIZE + TARGETID_SEEK + PACKGID_SIZE;
        private const long KEYPOL_SEEK =   DOMAINID_SIZE + ORIGINID_SIZE + TARGETID_SEEK + PACKGID_SIZE + PACKGTAG_SIZE;
        private const long OPTFLG_SEEK =   DOMAINID_SIZE + ORIGINID_SIZE + TARGETID_SEEK + PACKGID_SIZE + PACKGTAG_SIZE + KEYPOL_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// Domain identity; a 32 byte field that can describe the domain, a description, or contain a secret shared by a group. 
        /// <para>When combined with the KeyPolicy DomainRestrict flag, acts as an authentication key</para>
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = DOMAINID_SIZE)]
        public byte[] DomainId;
        /// <summary>
        /// Origin identity; a unique 16 byte value identifying the node that created this key
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = ORIGINID_SIZE)]
        public byte[] OriginId;
        /// <summary>
        /// Target identity; a unique 16 byte value identifying the target node
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = TARGETID_SIZE)]
        public byte[] TargetId;
        /// <summary>
        /// A unique 32 byte field identity of this package
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = PACKGID_SIZE)]
        public byte[] PackageId;
        /// <summary>
        /// A 32 byte field containing an optional package description or authentication code
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = PACKGTAG_SIZE)]
        public byte[] PackageTag;
        /// <summary>
        /// A <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">KeyPolicy</see> master flag that contains the policy flags applied to each sub key set
        /// </summary>
        public long KeyPolicy;
        /// <summary>
        /// Used by KeyPolicy if the flag is set to <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies.Volatile">Volatile</see>, set as the expiration date/time in Ticks
        /// </summary>
        public long OptionFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// KeyAuthority constructor.
        /// </summary>
        /// 
        /// <param name="DomainId">Domain identity; a 16 byte field that can describe the domain, a description, or contain a secret shared by a group</param>
        /// <param name="OriginId">Origin identity; a unique 16 byte value identifying the node that created this key</param>
        /// <param name="PackageId">A unique 16 byte field used for storage or as identity of this package</param>
        /// <param name="PackageTag">A 32 byte field containing an optional package description or authentication code</param>
        /// <param name="KeyPolicy">A <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">KeyPolicy</see> master flag that contains the policy flags applied to each subkey set</param>
        /// <param name="OptionFlag">Used by KeyPolicy if the flag is set to <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies.Volatile">Volatile</see>, set as the key expiration date/time in Ticks</param>
        /// <param name="TargetId">The hashed value of the targets origin id field, used to authenticate a target installation. A null value generates zeros.</param>
        public KeyAuthority(byte[] DomainId, byte[] OriginId, byte[] PackageId, byte[] PackageTag, KeyPolicies KeyPolicy, int OptionFlag = 0, byte[] TargetId = null)
        {
            this.DomainId = new byte[DOMAINID_SIZE];
            Array.Copy(DomainId, 0, this.DomainId, 0, DomainId.Length < DOMAINID_SIZE ? DomainId.Length : DOMAINID_SIZE);

            this.OriginId = new byte[ORIGINID_SIZE];
            Array.Copy(OriginId, 0, this.OriginId, 0, OriginId.Length < ORIGINID_SIZE ? OriginId.Length : ORIGINID_SIZE);

            this.TargetId = new byte[TARGETID_SIZE];
            if (TargetId != null)
                Array.Copy(TargetId, 0, this.TargetId, 0, TargetId.Length < TARGETID_SIZE ? TargetId.Length : TARGETID_SIZE);

            this.PackageId = new byte[PACKGID_SIZE];
            Array.Copy(PackageId, 0, this.PackageId, 0, PackageId.Length < PACKGID_SIZE ? PackageId.Length : PACKGID_SIZE);

            this.PackageTag = new byte[PACKGTAG_SIZE];
            Array.Copy(PackageTag, 0, this.PackageTag, 0, PackageTag.Length < PACKGTAG_SIZE ? PackageTag.Length : PACKGTAG_SIZE);

            this.KeyPolicy = (int)KeyPolicy;
            this.OptionFlag = OptionFlag;
        }

        /// <summary>
        /// Initialize the KeyAuthority structure using a Stream
        /// </summary>
        /// 
        /// <param name="AuthorityStream">The Stream containing the KeyAuthority</param>
        public KeyAuthority(Stream AuthorityStream)
        {
            BinaryReader reader = new BinaryReader(AuthorityStream);

            DomainId = reader.ReadBytes(DOMAINID_SIZE);
            OriginId = reader.ReadBytes(ORIGINID_SIZE);
            TargetId = reader.ReadBytes(TARGETID_SIZE);
            PackageId = reader.ReadBytes(PACKGID_SIZE);
            PackageTag = reader.ReadBytes(PACKGTAG_SIZE);
            KeyPolicy = reader.ReadInt64();
            OptionFlag = reader.ReadInt64();
        }

        /// <summary>
        /// Initialize the KeyAuthority structure using a byte array
        /// </summary>
        /// 
        /// <param name="AuthorityArray">The byte array containing the KeyAuthority</param>
        public KeyAuthority(byte[] AuthorityArray) :
            this (new MemoryStream(AuthorityArray))
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return AUTHDR_SIZE;
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="Authority">The stream containing a KeyAuthority structure</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(KeyAuthority Authority)
        {
            int count = 0;
            for (int i = 0; i < Authority.OriginId.Length; i++)
            {
                if (Authority.OriginId[i] == (byte)0)
                    count++;
            }

            return count < 8;
        }

        /// <summary>
        /// Reset all members of the KeyAuthority structure
        /// </summary>
        public void Reset()
        {
            if (DomainId != null)
            {
                Array.Clear(DomainId, 0, DomainId.Length);
                DomainId = null;
            }
            if (OriginId != null)
            {
                Array.Clear(OriginId, 0, OriginId.Length);
                OriginId = null;
            }
            if (TargetId != null)
            {
                Array.Clear(TargetId, 0, TargetId.Length);
                TargetId = null;
            }
            if (PackageId != null)
            {
                Array.Clear(PackageId, 0, PackageId.Length);
                PackageId = null;
            }
            if (PackageTag != null)
            {
                Array.Clear(PackageTag, 0, PackageTag.Length);
                PackageTag = null;
            }

            KeyPolicy = 0;
            OptionFlag = 0;
        }

        /// <summary>
        /// Convert the KeyAuthority structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the KeyAuthority</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the KeyAuthority structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the KeyAuthority</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(DomainId);
            writer.Write(OriginId);
            writer.Write(TargetId);
            writer.Write(PackageId);
            writer.Write(PackageTag);
            writer.Write(KeyPolicy);
            writer.Write(OptionFlag);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
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
            int hash = ArrayUtils.GetHashCode(DomainId);
            hash += ArrayUtils.GetHashCode(OriginId);
            hash += ArrayUtils.GetHashCode(TargetId);
            hash += ArrayUtils.GetHashCode(PackageId);
            hash += ArrayUtils.GetHashCode(PackageTag);
            hash += (int)(31 * KeyPolicy);
            hash += (int)(31 * OptionFlag);

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
            if (!(Obj is KeyAuthority))
                return false;

            KeyAuthority other = (KeyAuthority)Obj;

            if (!Compare.IsEqual(DomainId, other.DomainId))
                return false;
            if (!Compare.IsEqual(OriginId, other.OriginId))
                return false;
            if (!Compare.IsEqual(TargetId, other.TargetId))
                return false;
            if (!Compare.IsEqual(PackageId, other.PackageId))
                return false;
            if (!Compare.IsEqual(PackageTag, other.PackageTag))
                return false;
            if (KeyPolicy != other.KeyPolicy)
                return false;
            if (OptionFlag != other.OptionFlag)
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
        public static bool operator ==(KeyAuthority X, KeyAuthority Y)
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
        public static bool operator !=(KeyAuthority X, KeyAuthority Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
    #endregion
}
