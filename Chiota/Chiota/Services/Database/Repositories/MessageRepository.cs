using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class MessageRepository : SecureRepository<DbMessage>
    {
        #region Constructors

        public MessageRepository(SQLiteConnection database, string key, string salt) : base(database, key, salt)
        {
        }

        #endregion

        #region GetMessageByChatAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbMessage> GetMessagesByChatAddress(string chatAddress)
        {
            try
            {
                var value = Encrypt(chatAddress);
                var query = Database.Query(TableMapping,
                    "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=?;", value).Cast<DbMessage>().ToList();

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
