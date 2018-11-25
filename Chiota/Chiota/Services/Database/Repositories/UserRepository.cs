using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class UserRepository : SecureRepository<DbUser>
    {
        #region Constructors

        public UserRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion
    }
}
