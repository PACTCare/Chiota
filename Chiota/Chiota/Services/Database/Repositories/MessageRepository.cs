using System;
using System.Collections.Generic;
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
                var query = (IEnumerable<DbMessage>) Database.Query(TableMapping,
                    "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.ChatAddress) + "=" +
                    value + ";");
                var models = new List<DbMessage>(query);

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
