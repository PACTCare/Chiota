using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Messenger.Repository;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class ContactRepository : SecureRepository<DbContact>
    {
        #region Constructors

        public ContactRepository(SQLiteConnection database, string key, string salt) : base(database, key, salt)
        {
        }

        #endregion

        #region GetAcceptedContactByPublicKeyAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetAcceptedContactsByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = (IEnumerable<DbContact>) Database.Query(TableMapping,
                    "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=" +
                    value + " AND " + nameof(DbContact.Accepted) + "=TRUE;");
                var models = new List<DbContact>(query);

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
