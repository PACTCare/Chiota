#region References

using System;
using System.Collections.Generic;
using System.Linq;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Models.Database.Cache;
using Chiota.Services.Database.Base;
using SQLite;

#endregion

namespace Chiota.Services.Database.Repositories.Cache
{
    public class ContactCacheRepository : SecureRepository<DbContactCache>
    {
        #region Constructors

        public ContactCacheRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion

        #region GetAcceptedContactCachesByPublicKeyAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbContactCache> GetAcceptedContactCachesByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=? AND " + nameof(DbContact.Accepted) + "=1;", value).Cast<DbContactCache>().ToList();

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

        #region GetContactCacheByPublicKeyAddress

        /// <summary>
        /// Get an contact by his public key address of the user.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public DbContactCache GetContactCacheByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=?", value) as DbContactCache;

                DecryptModel(query);

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
