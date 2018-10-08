using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Messenger.Repository;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;

namespace Chiota.Services.Database.Repositories
{
    public class ContactRepository : SecureRepository<DbContact>
    {
        #region Constructors

        public ContactRepository(DatabaseContext context, string key, string salt) : base(context, key, salt)
        {
        }

        #endregion

        #region GetAcceptedContactByPublicKeyAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetAcceptedContactByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var models = QueryObjects(t => t.PublicKeyAddress == value && t.Accepted == true);

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
    }
}
