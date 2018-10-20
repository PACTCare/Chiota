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
        #region Attributes

        private static SQLiteConnection _database;
        private static string _key;
        private static string _salt;

        #endregion

        #region Properties

        public static TransactionCacheRepository TransactionCache { get; private set; }
        public static UserRepository User { get; private set; }
        public static ContactRepository Contact { get; private set; }
        public static MessageRepository Message { get; private set; }

        public static string Name { get; }

        #endregion

        #region Constructors

        static DatabaseService()
        {
            Name = (string)Application.Current.Resources["AppName"];

            //Dynamic connection to the database.
            _database = DependencyService.Get<ISqlite>().GetDatabaseConnection();

            Init();
        }

        #endregion

        #region Init

        public static void Init()
        {
            TransactionCache = new TransactionCacheRepository(_database, _key, _salt);
            User = new UserRepository(_database, _key, _salt);
            Contact = new ContactRepository(_database, _key, _salt);
            Message = new MessageRepository(_database, _key, _salt);
        }

        #endregion

        #region SetEncryptionKey

        public static void SetEncryptionKey(string key, string salt)
        {
            _key = key;
            _salt = salt;

            Init();
        }

        #endregion
    }
}
