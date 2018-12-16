#region References

using System;
using System.IO;
using Chiota.Services.Database.Base;
using Chiota.UWP.Services.Database;
using SQLite;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(Sqlite))]
namespace Chiota.UWP.Services.Database
{
    public class Sqlite : ISqlite
    {
        private SQLiteConnection _connection;

        public string GetDatabasePath()
        {
            var databasePath = Path.Combine(Windows.Storage.ApplicationData.Current.LocalFolder.Path, "Chiota" + ".db");
            return databasePath;
        }

        public SQLiteConnection GetDatabaseConnection()
        {
            var databasePath = GetDatabasePath();
            _connection = new SQLiteConnection(databasePath);
            return _connection;
        }

        public bool CloseDatabaseConnection()
        {
            if (_connection == null) return false;
            _connection.Close();
            _connection.Dispose();
            _connection = null;

            //Activate the garbage collector to delete unused resources
            GC.Collect();
            GC.WaitForPendingFinalizers();
            return true;
        }

        public bool DeleteDatabase()
        {
            var databasePath = GetDatabasePath();

            try
            {
                _connection?.Close();

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
