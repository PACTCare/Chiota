using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Tangle.Net.Entity;
using Xamarin.Essentials;

namespace Chiota.Services.Database.Base
{
    public abstract class BaseRepository<T> where T : BaseModel
    {
        #region Constructors

        protected BaseRepository()
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
        public virtual async Task<T> GetObjectAsync(string key)
        {
            try
            {
                var value = await SecureStorage.GetAsync(key);
                var result = JsonConvert.DeserializeObject<T>(value);

                return result;
            }
            catch (Exception)
            {
                return null;
            }
        }

        #endregion

        #region SetObject

        /// <summary>
        /// Set an object to the database.
        /// If it fails, the method will return false.
        /// </summary>
        /// <returns></returns>
        public virtual async Task<bool> SetObjectAsync(string key, T model)
        {
            try
            {
                //First we need to try to open hte table.
                //If it does not exist, we need to create one.
                var data = await GetObjectAsync(key);

                if (data != null)
                {
                    //The data exists, we need to remove it, before we can safe the new one.
                    SecureStorage.Remove(key);
                }

                //Create the data.
                var jsonModel = JsonConvert.SerializeObject(model);
                await SecureStorage.SetAsync(key, jsonModel);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion

        #region RemoveObject

        public virtual bool RemoveObject(string key)
        {
            try
            {
                var result = SecureStorage.Remove(key);
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
