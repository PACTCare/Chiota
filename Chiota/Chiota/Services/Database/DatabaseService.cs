using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Services.Database.Repositories;
using Xamarin.Essentials;

namespace Chiota.Services.Database
{
    public static class DatabaseService
    {
        #region Properties

        public static DatabaseInfoRepository DatabaseInfo { get; }
        public static UserRepository User { get; }

        #endregion

        #region Constructor

        static DatabaseService()
        {
            DatabaseInfo = new DatabaseInfoRepository();
            User = new UserRepository();
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Initialize all important database repositories.
        /// </summary>
        /// <returns></returns>
        public static void Init()
        {
            var task = Task.Run(async () =>
            {
                try
                {
                    await DatabaseInfo.InitAsync();
                }
                catch (Exception)
                {
                    // ignored
                }
            });
            task.Wait();
        }

        #endregion

        #region Delete

        /// <summary>
        /// Delete the database.
        /// </summary>
        /// <returns></returns>
        public static bool Delete()
        {
            try
            {
                //Delete the database.
                SecureStorage.RemoveAll();

                //Initialize the database.
                Init();

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion

        #endregion
    }
}
