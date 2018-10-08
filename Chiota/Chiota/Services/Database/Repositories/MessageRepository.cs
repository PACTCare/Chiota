using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;

namespace Chiota.Services.Database.Repositories
{
    public class MessageRepository : SecureRepository<DbMessage>
    {
        #region Constructors

        public MessageRepository(DatabaseContext context, string key, string salt) : base(context, key, salt)
        {
        }

        #endregion

        #region GetMessageByChatAddress

        /// <summary>
        /// Get all objects of the table by the public key address.
        /// </summary>
        /// <returns>List of the table objects</returns>
        public List<DbMessage> GetMessageByChatAddress(string chatAddress)
        {
            try
            {
                var value = Encrypt(chatAddress);
                var models = QueryObjects(t => t.ChatAddress == value);

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
