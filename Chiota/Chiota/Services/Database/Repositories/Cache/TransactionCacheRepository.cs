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
    public class TransactionCacheRepository : SecureRepository<DbTransactionCache>
    {
        #region Constructors

        public TransactionCacheRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion

        #region GetTransactionCacheByChatAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbTransactionCache> GetTransactionCacheByChatAddress(string chatAddress)
        {
            try
            {
                var value = Encrypt(chatAddress);
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=?;", value).Cast<DbTransactionCache>().ToList();

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
