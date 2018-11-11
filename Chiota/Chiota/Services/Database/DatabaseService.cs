using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models;
using Chiota.Services.Database.Base;
using Chiota.Services.Database.Repositories;
using SQLite;
using Xamarin.Forms;

namespace Chiota.Services.Database
{
    public class DatabaseService
    {
        #region Properties

        public TransactionCacheRepository TransactionCache { get; }
        public UserRepository User { get; }
        public ContactRepository Contact { get; }
        public MessageRepository Message { get; }

        #endregion

        #region Constructors

        public DatabaseService(ISqlite sqlite, EncryptionKey encryptionKey)
        {
            //Dynamic connection to the database.
            var database = sqlite.GetDatabaseConnection();

            TransactionCache = new TransactionCacheRepository(database, encryptionKey);
            User = new UserRepository(database, encryptionKey);
            Contact = new ContactRepository(database, encryptionKey);
            Message = new MessageRepository(database, encryptionKey);
        }

        #endregion
    }
}
