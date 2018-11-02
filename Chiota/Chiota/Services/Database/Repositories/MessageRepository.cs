using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class MessageRepository : TableRepository<DbMessage>
    {
        #region Constructors

        public MessageRepository(SQLiteConnection database) : base(database)
        {
        }

        #endregion
    }
}
