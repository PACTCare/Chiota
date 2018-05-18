#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// Drive methods wrapper class
    /// </summary>
    public sealed class DriveTools
    {
        #region Drive Tools
        /// <summary>
        /// Get Total Drive space
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static long GetSize(string DrivePath)
        {
            if (!string.IsNullOrEmpty(DrivePath))
            {
                DriveInfo d = new DriveInfo(DrivePath);

                if (d.IsReady)
                    return d.TotalSize;
            }
            return 0;
        }

        /// <summary>
        /// Get Drive Free space
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static long GetFreeSpace(string DrivePath)
        {
            if (!string.IsNullOrEmpty(DrivePath))
            {
                DriveInfo d = new DriveInfo(DrivePath);

                if (d.IsReady)
                    return d.AvailableFreeSpace;
            }
            return 0;
        }

        /// <summary>
        /// Get Drive Free space
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static long GetFreeSpaceMB(string DrivePath)
        {
            if (!string.IsNullOrEmpty(DrivePath))
            {
                DriveInfo d = new DriveInfo(DrivePath);

                if (d.IsReady)
                {
                    double bytes = d.AvailableFreeSpace;
                    double divisor = Math.Pow(1024, 2);

                    return (bytes > divisor) ? (long)(bytes / divisor) : 0;
                }
            }
            return 0;
        }

        /// <summary>
        /// Get the drive path from a directory or file path
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Path</param>
        /// 
        /// <returns>Result</returns>
        public static string GetPath(string DirectoryPath)
        {
            return (!string.IsNullOrEmpty(DirectoryPath) ? Path.GetPathRoot(DirectoryPath) : string.Empty);
        }

        /// <summary>
        /// Drive is available
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static bool IsReady(string DrivePath)
        {
            return (!string.IsNullOrEmpty(DrivePath)) ? new DriveInfo(DrivePath).IsReady : false;
        }
        #endregion
    }
}
