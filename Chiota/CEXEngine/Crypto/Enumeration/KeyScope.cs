namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Key authentication scope. 
    /// <para>Indicates at which privilege level the key can be accessed. 
    /// Used by the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory"/> class as an access level description.</para>
    /// </summary>
    public enum KeyScope : int
    {
        /// <summary>
        /// Creator of this key; full access
        /// </summary>
        Creator = 1,
        /// <summary>
        /// Key recipient; decrypt only access
        /// </summary>
        Operator = 2,
        /// <summary>
        /// The operator is denied access to this key
        /// </summary>
        NoAccess = 4
    }
}
