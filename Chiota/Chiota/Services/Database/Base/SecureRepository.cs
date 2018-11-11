using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Chiota.Models;
using Chiota.Models.Database.Base;
using Chiota.Services.Security;
using SQLite;

namespace Chiota.Services.Database.Base
{
    public abstract class SecureRepository<T> : TableRepository<T> where T : TableModel
    {
        #region Attributes

        protected EncryptionKey EncryptionKey { get; }

        #endregion

        #region Constructors

        protected SecureRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database)
        {
            EncryptionKey = encryptionKey;
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
                    models[i] = DecryptModel(models[i]);

                return models;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

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
                model = DecryptModel(model);

                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetLastAddedObject

        /// <summary>
        /// Get the last added object in the database.
        /// </summary>
        /// <returns></returns>
        public override T GetLastAddedObject()
        {
            try
            {
                var last = base.GetLastAddedObject();
                last = DecryptModel(last);
                return last;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

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
                var encrypted = EncryptModel(t);
                var model = base.AddObject(encrypted);
                return model;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

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
                var encrypted = EncryptModel(t);
                var result = base.UpdateObject(encrypted);
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

        #region SecurityMethods

        #region Encrypt

        protected T EncryptModel(T t)
        {
            foreach (var property in t.GetType().GetProperties())
            {
                if (property.PropertyType == typeof(string))
                {
                    var value = (string)property.GetValue(t);
                    if (string.IsNullOrEmpty(value)) continue;

                    var encrypted = Encrypt(value);
                    property.SetValue(t, encrypted);
                }
            }

            return t;
        }

        protected string Encrypt(string value)
        {
            var encrypted = Encryption.Encrypt(value, EncryptionKey.Value, EncryptionKey.Salt);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(encrypted));
        }

        #endregion

        #region Decrypt

        protected T DecryptModel(T t)
        {
            foreach (var property in t.GetType().GetProperties())
            {
                if (property.PropertyType == typeof(string))
                {
                    var value = (string)property.GetValue(t);
                    if (string.IsNullOrEmpty(value)) continue;

                    var encrypted = Decrypt(value);
                    property.SetValue(t, encrypted);
                }
            }

            return t;
        }

        protected string Decrypt(string value)
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(value));
            return Encryption.Decrypt(text, EncryptionKey.Value, EncryptionKey.Salt);
        }

        #endregion

        #endregion
    }
}
