using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Services.Database.Base;

namespace Chiota.Services.Database.Repositories
{
    public class DatabaseInfoRepository : BaseRepository<DatabaseInfo>
    {
        #region Attributes

        private const string Key = "databaseinfo";

        #endregion

        #region Constructors

        public DatabaseInfoRepository() : base()
        {
        }

        #endregion

        #region Methods

        #region GetObject

        /// <summary>
        /// Get an object, which is stored in the database.
        /// If it fails, the method will return null.
        /// </summary>
        /// <returns></returns>
        public async Task<DatabaseInfo> GetObjectAsync()
        {
            return await base.GetObjectAsync(Key);
        }

        #endregion

        #region SetObject

        /// <summary>
        /// Set an object to the database.
        /// If it fails, the method will return false.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> SetObjectAsync(DatabaseInfo model)
        {
            return await base.SetObjectAsync(Key, model);
        }

        #endregion

        #region RemoveObject

        public bool RemoveObject()
        {
            return base.RemoveObject(Key);
        }

        #endregion

        #region Init

        /// <summary>
        /// Initialize the database info for the local database.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> InitAsync()
        {
            var result = false;

            var existing = await GetObjectAsync(Key);
            if (existing != null)
                result = true;
            else
            {
                //There exist no database info, we need to create one.
                var value = new DatabaseInfo()
                {
                    UserStored = false
                };

                result = await SetObjectAsync(Key, value);
            }
            
            return result;
        }

        #endregion

        #region IsUserStored

        /// <summary>
        /// Returns information, if there is a user stored in the database.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> IsUserStoredAsync()
        {
            try
            {
                var value = await GetObjectAsync(Key);
                var result = value.UserStored;
                return result;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion

        #endregion
    }
}
