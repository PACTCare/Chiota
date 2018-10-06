using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Services.Database.Base;
using Chiota.Services.Database.Repositories;
using Xamarin.Forms;

namespace Chiota.Services.Database
{
    public static class DatabaseService
    {
        #region Properties

        public static UserRepository User { get; private set; }

        public static string Name { get; }
        
        private static DatabaseContext _databaseContext;
        private static string _key;

        #endregion

        #region Constructors

        static DatabaseService()
        {
            Name = (string)Application.Current.Resources["AppName"];

            //Dynamic filepath of the database
            var databasePath = DependencyService.Get<ISqlite>().GetDatabasePath();
            _databaseContext = new DatabaseContext(databasePath);

            Init();
        }

        #endregion

        #region Init

        private static void Init()
        {
            User = new UserRepository(_databaseContext, _key);
        }

        #endregion

        #region SetEncryptionKey

        public static void SetEncryptionKey(string key)
        {
            _key = key;

            Init();
        }

        #endregion
    }
}
