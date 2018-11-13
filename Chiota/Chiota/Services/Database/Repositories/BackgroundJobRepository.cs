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
        #region Constructors

        public BackgroundJobRepository(SQLiteConnection database, EncryptionKey encryptionKey) : base(database, encryptionKey)
        {
        }

        #endregion

        #region GetBackgroundJobByName

        public DbBackgroundJob GetBackgroundJobByName(string name)
        {
            try
            {
                var value = Encrypt(name);
                var query = Database.FindWithQuery(TableMapping, "SELECT * FROM " + TableMapping.TableName + " WHERE " + nameof(DbBackgroundJob.Name) + "=?;", value) as DbBackgroundJob;

                query = DecryptModel(query);

                return query;
            }
            catch (Exception)
            {
                return null;
            }
        }

        #endregion
    }
}
