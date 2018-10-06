using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;
using Microsoft.EntityFrameworkCore;

namespace Chiota.Services.Database.Repositories
{
    public class UserRepository : SecureRepository<DbUser>
    {
        #region Constructors

        public UserRepository(DatabaseContext context, string key) : base(context, key)
        {
        }

        #endregion

        #region IsUserStored

        public bool IsUserStored()
        {
            var result = DatabaseContext.Set<DbUser>().Any();
            return result;
        }

        public async Task<bool> IsUserStoredAsync()
        {
            var result = await DatabaseContext.Set<DbUser>().AnyAsync();
            return result;
        }

        #endregion
    }
}
