using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Chiota.Droid.Services.Database;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using SQLite;
using Xamarin.Forms;

[assembly: Dependency(typeof(Sqlite))]
namespace Chiota.Droid.Services.Database
{
    public class Sqlite : ISqlite
    {
        private SQLiteConnection _connection;

        public string GetDatabasePath()
        {
            string documentsPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Personal); // Documents folder
            var path = Path.Combine(documentsPath, DatabaseService.Name + ".db");

            return path;
        }

        public SQLiteConnection GetDatabaseConnection()
        {
            var databasePath = GetDatabasePath();
            _connection = new SQLiteConnection(databasePath);
            return _connection;
        }

        public bool CloseDatabaseConnection()
        {
            if (_connection != null)
            {
                _connection.Close();
                _connection.Dispose();
                _connection = null;

                //Activate the garbage collector to delete unused resources
                GC.Collect();
                GC.WaitForPendingFinalizers();
                return true;
            }
            return false;
        }

        public bool DeleteDatabase()
        {
            var databasePath = GetDatabasePath();

            try
            {
                if (_connection != null)
                    _connection.Close();

                if (File.Exists(databasePath))
                    File.Delete(databasePath);

                _connection = null;

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }
    }
}