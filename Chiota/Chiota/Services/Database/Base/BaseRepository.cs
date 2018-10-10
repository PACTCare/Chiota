using System;
using System.Collections.Generic;
using System.Text;
using SQLite;

namespace Chiota.Services.Database.Base
{
    public abstract class BaseRepository
    {
        #region Attributes

        //Database context
        protected readonly SQLiteConnection Database;

        #endregion

        /// <summary>
        /// Base constructor of the database Repositories.
        /// Controls the access of the different database tables.
        /// </summary>
        /// <param name="database">Context of the local database.</param>
        protected BaseRepository(SQLiteConnection database)
        {
            Database = database;
        }
    }
}
