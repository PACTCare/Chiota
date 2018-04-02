#region Directives
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// Folder methods wrapper class
    /// </summary>
    public sealed class DirectoryUtils
    {
        #region Constructor
        private DirectoryUtils() { }
        #endregion

        #region Directory Tools
        /// <summary>
        /// Create a folder
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryCreate(string DirectoryPath)
        {
            return (!string.IsNullOrEmpty(DirectoryPath)) ? Directory.CreateDirectory(DirectoryPath).Exists : false;
        }

        /// <summary>
        /// Test for directory and create
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryChecked(string DirectoryPath)
        {
            if (!string.IsNullOrEmpty(DirectoryPath)) return false;
            return Directory.Exists(DirectoryPath) ? true : DirectoryCreate(DirectoryPath);
        }

        /// <summary>
        /// Test for directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryExists(string DirectoryPath)
        {
            bool b = Directory.Exists(DirectoryPath);
            return (!string.IsNullOrEmpty(DirectoryPath)) ? Directory.Exists(DirectoryPath) : false;
        }

        /// <summary>
        /// Get the number of files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full directory path</param>
        /// 
        /// <returns>Count</returns>
        public static int DirectoryGetFileCount(string DirectoryPath)
        {
            string[] filePaths = DirectoryGetFiles(DirectoryPath);
            return filePaths == null ? 0 : filePaths.Length;
        }

        /// <summary>
        /// Return all the files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// 
        /// <returns>File names [string]]</returns>
        public static string[] DirectoryGetFiles(string DirectoryPath)
        {
            try
            {
                return (DirectoryExists(DirectoryPath)) ? Directory.GetFiles(DirectoryPath) : null;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Get common directories
        /// </summary>
        /// 
        /// <param name="FolderPath">Folder enum</param>
        /// 
        /// <returns>Directory [string]</returns>
        public static string DirectoryGetCommon(Environment.SpecialFolder FolderPath)
        {
            try
            {
                return Environment.GetFolderPath(FolderPath);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Get file directory from path
        /// </summary>
        /// 
        /// <param name="FilePath">File path</param>
        /// 
        /// <returns>Directory [string]</returns>
        public static string DirectoryGetPath(string FilePath)
        {
            return (!string.IsNullOrEmpty(FilePath)) ? Path.GetDirectoryName(FilePath) : string.Empty;
        }

        /// <summary>
        /// Return all the files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// 
        /// <returns>File names [string]]</returns>
        public static long DirectoryGetSize(string DirectoryPath)
        {
            if (!DirectoryExists(DirectoryPath)) return -1;
            long size = 0;

            try
            {
                string[] files = Directory.GetFiles(DirectoryPath, "*.*", SearchOption.AllDirectories);

                foreach (var file in files)
                    size += FileUtils.FileGetSize(file);

                return size;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Test a directory for create file access permissions
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to file or directory </param>
        /// <param name="AccessRight">File System right tested</param>
        /// 
        /// <returns>State</returns>
        public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
        {
            if (string.IsNullOrEmpty(DirectoryPath)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Directory can write/create
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryIsWritable(string DirectoryPath)
        {
            try
            {
                if (!DirectoryExists(DirectoryPath)) return false;

                string path = Path.Combine(DirectoryPath, Path.GetRandomFileName());
                using (FileStream fs = File.Create(path, 1, FileOptions.DeleteOnClose))
                    return File.Exists(path);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test a directory for create file access permissions
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full directory path</param>
        /// 
        /// <returns>State</returns>
        public static bool DirectoryCanCreate(string DirectoryPath)
        {
            if (string.IsNullOrEmpty(DirectoryPath)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((FileSystemRights.CreateFiles & rule.FileSystemRights) == FileSystemRights.CreateFiles)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test a directory for write file access permissions
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full directory path</param>
        /// 
        /// <returns>State</returns>
        public static bool DirectoryCanWrite(string DirectoryPath)
        {
            if (string.IsNullOrEmpty(DirectoryPath)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((FileSystemRights.Write & rule.FileSystemRights) == FileSystemRights.Write)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        #endregion

        #region Directory Security
        /// <summary>
        /// Add an access rule to a folder
        /// </summary>
        /// 
        /// <param name="Path">Folder path</param>
        /// <param name="User">UNC path to user profile ex. Environment.UserDomainName + "\\" + Environment.UserName</param>
        /// <param name="Rights">Desired file system rights</param>
        /// <param name="Access">Desired level of access</param>
        public static void DirectoryAddAccessRule(string Path, string User, FileSystemRights Rights, AccessControlType Access)
        {
            // Get a DirectorySecurity object that represents the current security settings
            System.Security.AccessControl.DirectorySecurity sec = System.IO.Directory.GetAccessControl(Path);
            // Add the FileSystemAccessRule to the security settings
            FileSystemAccessRule accRule = new FileSystemAccessRule(User, Rights, Access);
            sec.AddAccessRule(accRule);
        }

        /// <summary>
        /// Add a file system right to a directory
        /// </summary>
        /// 
        /// <param name="Path">Full path to directory</param>
        /// <param name="Account">UNC path to user profile</param>
        /// <param name="Rights">Desired file system rights</param>
        /// <param name="ControlType">Access control type</param>
        public static void DirectoryAddSecurity(string Path, string Account, FileSystemRights Rights, AccessControlType ControlType)
        {
            // Create a new DirectoryInfo object
            DirectoryInfo dInfo = new DirectoryInfo(Path);
            // Get a DirectorySecurity object that represents the current security settings
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            // Add the FileSystemAccessRule to the security settings
            dSecurity.AddAccessRule(new FileSystemAccessRule(Account, Rights, ControlType));
            // Set the new access settings
            dInfo.SetAccessControl(dSecurity);
        }

        /// <summary>
        /// Get access rules for a folder
        /// </summary>
        /// 
        /// <param name="Path">Folder path</param>
        /// <param name="Account">UNC path to user profile</param>
        /// 
        /// <returns>Rule collection [AuthorizationRuleCollection]</returns>
        public static AuthorizationRuleCollection DirectoryGetAccessRules(string Path, string Account)
        {
            DirectoryInfo dInfo = new DirectoryInfo(Path);
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            return dSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
        }

        /// <summary>
        /// Remove a file system right to a directory
        /// </summary>
        /// 
        /// <param name="FileName">Full path to directory</param>
        /// <param name="Account">UNC path to user profile</param>
        /// <param name="Rights">Desired file system rights</param>
        /// <param name="ControlType">Access control type</param>
        public static void DirectoryRemoveSecurity(string FileName, string Account, FileSystemRights Rights, AccessControlType ControlType)
        {
            // Create a new DirectoryInfo object.
            DirectoryInfo dInfo = new DirectoryInfo(FileName);
            // Get a DirectorySecurity object that represents the current security settings  
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            // Add the FileSystemAccessRule to the security settings
            dSecurity.RemoveAccessRule(new FileSystemAccessRule(Account, Rights, ControlType));
            // Set the new access settings
            dInfo.SetAccessControl(dSecurity);
        }
        #endregion
    }
}
