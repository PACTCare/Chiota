using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Services.Database.Base
{
    public abstract class BaseRepository
    {
        #region Attributes

        //Database context
        protected readonly DatabaseContext DatabaseContext;

        #endregion

        /// <summary>
        /// Base constructor of the database Repositories.
        /// Controls the access of the different database tables.
        /// </summary>
        /// <param name="context">Context of the local database.</param>
        protected BaseRepository(DatabaseContext context)
        {
            this.DatabaseContext = context;
        }
    }
}
