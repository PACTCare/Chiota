using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models.Database.Base;
using Chiota.Services.Security;
using Microsoft.EntityFrameworkCore;

namespace Chiota.Services.Database.Base
{
    public abstract class SecureRepository<T> : TableRepository<T> where T : TableModel
    {
        #region Attributes

        protected string Key { get; }

        #endregion

        #region Constructors

        protected SecureRepository(DatabaseContext context, string key) : base(context)
        {
            Key = key;
        }

        #endregion

        #region Methods

        #region GetObjects

        /// <summary>
        /// Get all objects of the table.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public override List<T> GetObjects()
        {
            try
            {
                var models = base.GetObjects();

                for (var i = 0; i < models.Count; i++)
                    models[i] = Decrypt(models[i]);

                return models;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #region GetObjectsAsync

        /// <summary>
        /// Get all objects of the table.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public override async Task<List<T>> GetObjectsAsync()
        {
            try
            {
                var models = await base.GetObjectsAsync();

                for (var i = 0; i < models.Count; i++)
                    models[i] = Decrypt(models[i]);
                
                return models;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #endregion

        #region GetObjectById

        /// <summary>
        /// Get specific object by id.
        /// </summary>
        /// <param name="id">Id of the object as integer</param>
        /// <returns>Object of the table</returns>
        public override T GetObjectById(int id)
        {
            try
            {
                var model = base.GetObjectById(id);
                model = Decrypt(model);

                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #region GetObjectByIdAsync

        /// <summary>
        /// Get specific object by id.
        /// </summary>
        /// <param name="id">Id of the object as integer</param>
        /// <returns>Object of the table</returns>
        public override async Task<T> GetObjectByIdAsync(int id)
        {
            try
            {
                var model = await base.GetObjectByIdAsync(id);
                model = Decrypt(model);

                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #endregion

        #region AddObject

        /// <summary>
        /// Add new object to the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful insert as boolean</returns>
        public override T AddObject(T t)
        {
            try
            {
                var encrypted = Encrypt(t);
                var model = base.AddObject(encrypted);
                var decrypted = Decrypt(model);
                return decrypted;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #region AddObjectAsync

        /// <summary>
        /// Add new object to the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful insert as boolean</returns>
        public override async Task<T> AddObjectAsync(T t)
        {
            try
            {
                var encrypted = Encrypt(t);
                var model = await base.AddObjectAsync(encrypted);
                var decrypted = Decrypt(model);
                return decrypted;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #endregion

        #region UpdateObject

        /// <summary>
        /// Update specific object of the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful update as boolean</returns>
        public override bool UpdateObject(T t)
        {
            try
            {
                var encrypted = Encrypt(t);
                var result = base.UpdateObject(encrypted);
                Decrypt(t);
                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #region UpdateObjectAsync

        /// <summary>
        /// Update specific object of the table.
        /// </summary>
        /// <param name="t">Object of the table</param>
        /// <returns>Result of successful update as boolean</returns>
        public override async Task<bool> UpdateObjectAsync(T t)
        {
            try
            {
                var encrypted = Encrypt(t);
                var result = await base.UpdateObjectAsync(encrypted);
                Decrypt(t);
                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #endregion

        #endregion

        #region DeleteObject

        /// <summary>
        /// Remove specific object of the table.
        /// </summary>
        /// <param name="id">Id of the object</param>
        /// <returns>Result of successful delete as boolean</returns>
        public override bool DeleteObject(int id)
        {
            try
            {
                return base.DeleteObject(id);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #region DeleteObjectAsync

        /// <summary>
        /// Remove specific object of the table.
        /// </summary>
        /// <param name="id">Id of the object</param>
        /// <returns>Result of successful delete as boolean</returns>
        public override async Task<bool> DeleteObjectAsync(int id)
        {
            try
            {
                return await base.DeleteObjectAsync(id);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        #endregion

        #endregion

        #endregion

        #region SecurityMethods

        #region Encrypt

        /// <summary>
        /// Encrypt the string properties of the given object by triple des.
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        private T Encrypt(T t)
        {
            foreach (var property in t.GetType().GetProperties())
            {
                if (property.PropertyType == typeof(string))
                {
                    var value = (string)property.GetValue(t);
                    if (string.IsNullOrEmpty(value)) continue;

                    var encrypted = TripleDes.Encrypt((string)value, Key);
                    property.SetValue(t, encrypted);
                }
            }

            return t;
        }

        #endregion

        /// <summary>
        /// Decrypt the string properties of the given object by triple des.
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        #region Decrypt

        private T Decrypt(T t)
        {
            foreach (var property in t.GetType().GetProperties())
            {
                if (property.PropertyType == typeof(string))
                {
                    var value = (string)property.GetValue(t);
                    if (string.IsNullOrEmpty(value)) continue;

                    var encrypted = TripleDes.Decrypt(value, Key);
                    property.SetValue(t, encrypted);
                }
            }

            return t;
        }

        #endregion

        #endregion
    }
}
