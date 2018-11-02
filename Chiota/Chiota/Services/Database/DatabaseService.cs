using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Services.Database.Base;
using Chiota.Services.Database.Repositories;
using SQLite;
using Xamarin.Forms;

namespace Chiota.Services.Database
{
    public static class DatabaseService
    {
        #region Properties

        public static TransactionCacheRepository TransactionCache { get; }
        public static UserRepository User { get; }
        public static ContactRepository Contact { get; }
        public static MessageRepository Message { get; }

        public static string Name { get; }

        #endregion

        #region Constructors

        static DatabaseService()
        {
            Name = (string)Application.Current.Resources["AppName"];

            //Dynamic connection to the database.
            var database = DependencyService.Get<ISqlite>().GetDatabaseConnection();

            TransactionCache = new TransactionCacheRepository(database);
            User = new UserRepository(database);
            Contact = new ContactRepository(database);
            Message = new MessageRepository(database);
        }

        #endregion
    }
}
