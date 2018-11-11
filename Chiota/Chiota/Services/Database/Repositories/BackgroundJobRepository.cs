using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class BackgroundJobRepository : SecureRepository<DbBackgroundJob>
    {
        #region BackgroundJobRepository

        protected BackgroundJobRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion
    }
}
