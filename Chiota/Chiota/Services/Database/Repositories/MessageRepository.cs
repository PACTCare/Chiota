#region References

using System;
using System.Collections.Generic;
using System.Linq;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

#endregion

namespace Chiota.Services.Database.Repositories
{
    public class MessageRepository : SecureRepository<DbMessage>
    {
        #region Constructors

        public MessageRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion

        #region GetMessagesByChatAddress

        /// <summary>
        /// Get the messages by the chat address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbMessage> GetMessagesByChatAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=? ORDER BY " + nameof(DbMessage.Id) + ";", value).Cast<DbMessage>().ToList();

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

        #region GetLastMessagesByChatAddress

        /// <summary>
        /// Get the last message by the chat address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public DbMessage GetLastMessagesByChatAddress(string chatAddress)
        {
            try
            {
                var value = Encrypt(chatAddress);
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=? ORDER BY " + nameof(DbMessage.Id) + " DESC LIMIT 1;", value) as DbMessage;

                query = DecryptModel(query);

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
