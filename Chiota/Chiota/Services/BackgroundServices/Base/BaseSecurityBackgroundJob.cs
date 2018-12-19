#region Reference

using System;
using System.Text;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Models.Database.Base;
using Chiota.Services.Security;

#endregion

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseSecurityBackgroundJob : BaseBackgroundJob
    {
        #region Attributes

        protected EncryptionKey EncryptionKey;

        #endregion

        #region Init

        public override void Init(params object[] data)
        {
            base.Init(data);

            if (data.Length == 0) return;

            foreach (var item in data)
            {
                switch (item)
                {
                    case DbUser user:
                        EncryptionKey = user.EncryptionKey;
                        break;
                }
            }
        }

        #endregion

        #region SecurityMethods

        #region Encrypt

        protected T EncryptModel<T>(T t) where T : BaseModel
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

        protected T DecryptModel<T>(T t) where T : BaseModel
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
