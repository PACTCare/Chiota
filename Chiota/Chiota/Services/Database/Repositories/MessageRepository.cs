using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class MessageRepository : SecureRepository<DbMessage>
    {
        #region Constructors

        public MessageRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion

        #region GetMessagesCountByPublicKeyAddress

        /// <summary>
        /// Get first object of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public int GetMessagesCountByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = (int)Database.FindWithQuery(TableMapping, "SELECT COUNT(*) FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.PublicKeyAddress) + "=?;", value);

                return query;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return 0;
            }
        }

        #endregion

        #region GetMessagesByPublicKeyAddress

        /// <summary>
        /// Get the last message by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbMessage> GetMessagesByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = Database.Query(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.PublicKeyAddress) + "=? ORDER BY " + nameof(DbMessage.Id) + " DESC LIMIT 1;", value).Cast<DbMessage>().ToList();

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

        #region GetLastMessagesByPublicKeyAddress

        /// <summary>
        /// Get the last message by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public DbMessage GetLastMessagesByPublicKeyAddress(string publicKeyAddress)
        {
            try
            {
                var value = Encrypt(publicKeyAddress);
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbMessage.PublicKeyAddress) + "=? ORDER BY " + nameof(DbMessage.Id) + " DESC LIMIT 1;", value) as DbMessage;

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
