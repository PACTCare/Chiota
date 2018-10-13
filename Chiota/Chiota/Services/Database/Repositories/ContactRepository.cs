using System;
using System.Collections.Generic;
using System.Linq;
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
                var query = Database.Query(TableMapping,
                    "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=? AND " + nameof(DbContact.Accepted) + "=1;", value).Cast<DbContact>().ToList();

                for (var i = 0; i < query.Count; i++)
                    query[i] = DecryptModel(query[i]);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        #endregion

        #region GetContactsOrderByAcceptedDesc

        /// <summary>
        /// Get all objects of the table order by accepted desc.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContact> GetContactsOrderByAcceptedDesc()
        {
            try
            {
                var query = Database.Query(TableMapping,
                    "SELECT * FROM " + TableMapping.TableName + " ORDER BY " + nameof(DbContact.Accepted) + " DESC;").Cast<DbContact>().ToList();

                for (var i = 0; i < query.Count; i++)
                    query[i] = DecryptModel(query[i]);

                return query;
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
