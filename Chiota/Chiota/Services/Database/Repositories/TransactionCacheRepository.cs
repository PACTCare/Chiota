using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class TransactionCacheRepository : TableRepository<DbTransactionCache>
    {
        #region Constructors

        public TransactionCacheRepository(SQLiteConnection database) : base(database)
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
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=?;", chatAddress).Cast<DbTransactionCache>().ToList();
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
