#region References

using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using SQLite;

#endregion

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
