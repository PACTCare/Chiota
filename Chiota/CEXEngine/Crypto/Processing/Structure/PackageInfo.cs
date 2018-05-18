#region Directives
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    /// <summary>
    /// A structure containing information about a <see cref="PackageKey"/> file.
    /// <para>Used to display statistics about a PackageKeys current state.</para>
    /// </summary>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct PackageInfo
    {
        #region Constants
        private const int CIPH_SIZE = 40;
        #endregion

        #region Public Fields
        /// <summary>
        /// The <see cref="CipherDescription"/> structure containing a complete description of the cipher instance.
        /// </summary>
        [MarshalAs(UnmanagedType.Struct, SizeConst = CIPH_SIZE)]
        public CipherDescription Description;
        /// <summary>
        /// The creation date/time of this key
        /// </summary>
        public DateTime Created;
        /// <summary>
        /// The origin id as a Guid
        /// </summary>
        public Guid Origin;
        /// <summary>
        /// The package tag as a string
        /// </summary>
        public string Tag;
        /// <summary>
        /// The number of Key Sets contained in this key package file.
        /// </summary>
        public int SubKeyCount;
        /// <summary>
        /// A <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">Policies</see> array that contains the set of policy flags
        /// </summary>
        public List<KeyPolicies> Policies;
        /// <summary>
        /// The date/time this key expires
        /// </summary>
        public DateTime Expiration;
        #endregion

        #region Constructor
        /// <summary>
        /// Build the PackageInfo structure from a <see cref="PackageKey"/> file
        /// </summary>
        /// 
        /// <param name="Package">Populated PackageKey structure</param>
        public PackageInfo(PackageKey Package)
        {
            Description = Package.Description;
            Created = new DateTime(Package.CreatedOn);
            Origin = new Guid(Package.Authority.OriginId);
            string ptg = System.Text.Encoding.ASCII.GetString(Package.Authority.PackageTag);
            Tag = ptg.Replace("\0", String.Empty);
            SubKeyCount = Package.SubKeyCount;
            Policies = new List<KeyPolicies>();

            foreach (var flag in Enum.GetValues(typeof(KeyPolicies)))
            {
                if ((Package.Authority.KeyPolicy & (long)flag) == (long)flag)
                    Policies.Add((KeyPolicies)flag);
            }

            if (Package.Authority.OptionFlag == 0)
                Expiration = DateTime.MaxValue;
            else
                Expiration = new DateTime(Package.Authority.OptionFlag);
        }
        #endregion
    }
}
