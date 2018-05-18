#region Directives
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// Directory methods wrapper class
    /// </summary>
    public sealed class DirectoryTools
    {
        #region Constructor
        private DirectoryTools() { }
        #endregion

        #region Directory Tools
        /// <summary>
        /// Create a folder
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool Create(string DirectoryPath)
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
        public static bool Checked(string DirectoryPath)
        {
            if (!string.IsNullOrEmpty(DirectoryPath)) return false;
            return Directory.Exists(DirectoryPath) ? true : Create(DirectoryPath);
        }

        /// <summary>
        /// Test for directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool Exists(string DirectoryPath)
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
        public static int FileCount(string DirectoryPath)
        {
            string[] filePaths = GetFiles(DirectoryPath);
            return filePaths == null ? 0 : filePaths.Length;
        }

        /// <summary>
        /// Return all the files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// <param name="Option">Get all files (default) or only the top directory</param>
        /// <param name="Filter">Search file filter, default is all files</param>
        /// 
        /// <returns>File names [string]]</returns>
        public static string[] GetFiles(string DirectoryPath, SearchOption Option = SearchOption.AllDirectories, string Filter = "*.*" )
        {
            try
            {
                return (Exists(DirectoryPath)) ? Directory.GetFiles(DirectoryPath, Filter, Option) : null;
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
        public static string GetCommon(Environment.SpecialFolder FolderPath)
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
        public static string GetPath(string FilePath)
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
        public static long GetSize(string DirectoryPath)
        {
            if (!Exists(DirectoryPath)) return -1;
            long size = 0;

            try
            {
                string[] files = Directory.GetFiles(DirectoryPath, "*.*", SearchOption.AllDirectories);

                foreach (var file in files)
                    size += FileTools.GetSize(file);

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
        public static bool HasPermission(string DirectoryPath, FileSystemRights AccessRight)
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
        public static bool IsWritable(string DirectoryPath)
        {
            try
            {
                if (!Exists(DirectoryPath)) return false;

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
        public static bool CanCreate(string DirectoryPath)
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
        public static bool CanWrite(string DirectoryPath)
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
        public static void AddAccessRule(string Path, string User, FileSystemRights Rights, AccessControlType Access)
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
        public static void AddSecurity(string Path, string Account, FileSystemRights Rights, AccessControlType ControlType)
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
        public static AuthorizationRuleCollection GetAccessRules(string Path, string Account)
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
        public static void RemoveSecurity(string FileName, string Account, FileSystemRights Rights, AccessControlType ControlType)
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
