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
    public class TableRepository<T> where T : TableModel
    {
        #region Attributes

        protected string _key;

        #endregion

        #region Constructors

        protected TableRepository(string key = null)
        {
            if (string.IsNullOrEmpty(key))
                key = Seed.Random().Value;

            _key = key;
        }

        #endregion

        #region Methods

        #region GetObjects

        /// <summary>
        /// Get all objects, which are stored in the database.
        /// If it fails, the method will return null.
        /// </summary>
        /// <returns></returns>
        public async Task<List<T>> GetObjectsAsync()
        {
            try
            {
                var value = await SecureStorage.GetAsync(_key);
                var model = JsonConvert.DeserializeObject<List<T>>(value);

                return model;
            }
            catch (Exception)
            {
                return null;
            }
        }

        #endregion

        #region GetObjectById

        /// <summary>
        /// Get an object of an id, which is stored in the database.
        /// If it fails, the method will return null.
        /// </summary>
        /// <returns></returns>
        public async Task<T> GetObjectByIdAsync(int id)
        {
            try
            {
                var value = await SecureStorage.GetAsync(_key);
                var model = JsonConvert.DeserializeObject<List<T>>(value);
                var result = model.First(t => t.Id == id);

                return result;
            }
            catch (Exception)
            {
                return null;
            }
        }

        #endregion

        #region AddObject

        private async Task<bool> AddObjectAsync(T model)
        {
            try
            {
                //First we need to try to open hte table.
                //If it does not exist, we need to create one.
                var table = await GetObjectsAsync();
                JArray json = null;

                if (table == null)
                {
                    var jsonModel = JsonConvert.SerializeObject(model);

                    //Create the table.
                    json = new JArray { JObject.Parse(jsonModel) };
                }
                else
                {
                    var jsonTable = JsonConvert.SerializeObject(table);
                    var jsonModel = JsonConvert.SerializeObject(model);

                    json = JArray.Parse(jsonTable);
                    json.Add(JObject.Parse(jsonModel));

                    SecureStorage.Remove(_key);
                }



                return true;
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
