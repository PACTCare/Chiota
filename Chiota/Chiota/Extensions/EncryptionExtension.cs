#region References

using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models;
using Chiota.Models.Database.Base;
using Chiota.Services.Security;

#endregion

namespace Chiota.Extensions
{
    public static class EncryptionExtension
    {
        #region Methods

        #region EncryptValue

        /// <summary>
        /// Encrypt a specific string value, by an encryption key.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static string EncryptValue(this string value, EncryptionKey encryptionKey)
        {
            var encrypt = Encryption.Encrypt(value, encryptionKey.Value, encryptionKey.Salt);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(encrypt));
        }

        #endregion

        #region DecryptValue

        /// <summary>
        /// Decrypt a specific string value, by an encryption key.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static string DecryptValue(this string value, EncryptionKey encryptionKey)
        {
            var decrypt = Encoding.UTF8.GetString(Convert.FromBase64String(value));
            return Encryption.Decrypt(decrypt, encryptionKey.Value, encryptionKey.Salt);
        }

        #endregion

        #region EncryptObject

        /// <summary>
        /// Encrypt a specific object, by an encryption key.
        /// </summary>
        /// <param name="t"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static T EncryptObject<T>(this T t, EncryptionKey encryptionKey) where T: TableModel
        {
            foreach (var property in t.GetType().GetProperties())
            {
                if (property.PropertyType == typeof(string))
                {
                    var tmp = (string)property.GetValue(t);
                    if (string.IsNullOrEmpty(tmp)) continue;

                    var encrypted = tmp.EncryptValue(encryptionKey);
                    property.SetValue(t, encrypted);
                }
            }

            return t;
        }

        #endregion

        #region DecryptObject

        /// <summary>
        /// Decrypt a specific object, by an encryption key.
        /// </summary>
        /// <param name="t"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static T DecryptObject<T>(this T t, EncryptionKey encryptionKey) where T : TableModel
        {
            foreach (var property in t.GetType().GetProperties())
            {
                if (property.PropertyType == typeof(string))
                {
                    var tmp = (string)property.GetValue(t);
                    if (string.IsNullOrEmpty(tmp)) continue;

                    var encrypted = tmp.DecryptValue(encryptionKey);
                    property.SetValue(t, encrypted);
                }
            }

            return t;
        }

        #endregion

        #region EncryptObjectList

        /// <summary>
        /// Encrypt a specific list of objects, by an encryption key.
        /// </summary>
        /// <param name="t"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static List<T> EncryptObjectList<T>(this List<T> t, EncryptionKey encryptionKey) where T : TableModel
        {
            foreach (var item in t)
                item.EncryptObject(encryptionKey);

            return t;
        }

        #endregion

        #region DecryptObjectList

        /// <summary>
        /// Decrypt a specific list of objects, by an encryption key.
        /// </summary>
        /// <param name="t"></param>
        /// <param name="encryptionKey"></param>
        /// <returns></returns>
        public static List<T> DecryptObjectList<T>(this List<T> t, EncryptionKey encryptionKey) where T : TableModel
        {
            foreach (var item in t)
                item.DecryptObject(encryptionKey);

            return t;
        }

        #endregion

        #endregion
    }
}
