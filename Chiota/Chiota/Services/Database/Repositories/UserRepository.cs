using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

namespace Chiota.Services.Database.Repositories
{
    public class UserRepository : TableRepository<DbUser>
    {
        #region Constructors

        public UserRepository(SQLiteConnection database) : base(database)
        {
        }

        #endregion

        #region IsUserStored

        public bool IsUserStored()
        {
            var result = Database.Table<DbUser>();
            return result.Any();
        }

        #endregion
    }
}
