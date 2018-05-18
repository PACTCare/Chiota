#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// System utilities class
    /// </summary>
    public sealed class SystemUtils
    {
        #region Constructor
        private SystemUtils() { }
        #endregion

        #region Public Methods
        /// <summary>
        /// Test for 64 bit architecture
        /// </summary>
        /// 
        /// <returns>True if 64 bit architecture</returns>
        public static bool Is64Bit()
        {
            return Environment.Is64BitProcess;
        }

        /// <summary>
        /// Test for multi processor system
        /// </summary>
        /// 
        /// <returns>True if processor count i more than 1</returns>
        public static bool IsMultiProcessor()
        {
            return Environment.ProcessorCount > 1;
        }
        #endregion
    }
}