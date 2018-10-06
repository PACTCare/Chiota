using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Chiota.Services.Database.Base
{
    public interface ISqlite
    {
        #region Methods

        /// <summary>
        /// Returns the applications filepath 
        /// </summary>
        /// <returns>The file path as string</returns>
        string GetDatabasePath();

        /// <summary>
        /// Delivers synchronous access to SQLite database object 
        /// </summary>
        /// <returns>The SQLiteConnection object</returns>
        SqliteConnection GetDatabaseConnection();

        /// <summary>
        /// Determine the connection to the SQLite database object 
        /// </summary>
        /// <returns>The result as boolean</returns>
        bool CloseDatabaseConnection();

        /// <summary>
        /// Deletes the SQLite database object 
        /// </summary>
        /// <returns>The result as boolean</returns>
        bool DeleteDatabase();

        #endregion
    }
}
