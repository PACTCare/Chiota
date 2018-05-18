#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// KeyPolicy enumeration flags stored in a <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/> structure. 
    /// <para>Used to define how the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory"/> class manages access to a key package file.
    /// Values can be combined, and tested with the PackageKey HasPolicy(group, policy), SetPolicy(package, index, policy) and ClearPolicy(package, index, policy) methods.</para>
    /// </summary>
    [Flags]
    public enum KeyPolicies : long
    {
        /// <summary>
        /// No change to policy is applied. Will not change an existing policy, to clear a policy flag use the ClearPolicy(group, policy) method in PackageKey
        /// </summary>
        None = 0,
        /// <summary>
        /// Key package subkeys are only valid for only one cycle of decryption, after which the key is locked out
        /// </summary>
        SingleUse = 16,
        /// <summary>
        /// Key package is time sensitive. Expiration date (Ticks) of key is assigned to the OptionFlag in a PackageKey structure
        /// </summary>
        Volatile = 32,
        /// <summary>
        /// Key package subkeys are valid for only one cycle of decryption, after which the sub-key set is erased in the key package file.
        /// </summary>
        PostOverwrite = 64,
        /// <summary>
        /// An operator may be able to decrypt a file with this key, but information within the key package header should be considered sensitive
        /// </summary>
        NoNarrative = 128,
        /// <summary>
        /// Use of this key will be restricted to the domain id contained in the PackageKey structures DomainId parameter.
        /// </summary>
        DomainRestrict = 256,
        /// <summary>
        /// Domain id is set as the targets unique identity field, use is restricted to that node. Overrides the DomainRestrict flag.
        /// </summary>
        IdentityRestrict = 512,
        /// <summary>
        /// The key package may only be used by the creator
        /// </summary>
        NoExport = 1024,
        /// <summary>
        /// Master authenticator; key packages created with this flag can be used for encryption by anyone. Should be combined with identity or domain restrict flags, 
        /// and only be used for centralized key generation within a secured network or group framework.
        /// </summary>
        MasterAuth = 2048,
        /// <summary>
        /// If this flag is set, the PackageKey.KeyAuthority:TargetId field is set to the targets OriginId, and used to authenticate the operator. This is an encryption flag.
        /// </summary>
        PackageAuth = 4096,
        /// <summary>
        /// This key has been used to encrypt a file volume. Volume keys can not decrypt an individual file inside the local volume, but must export the file.
        /// </summary>
        VolumeKey = 8192,
    }
}
