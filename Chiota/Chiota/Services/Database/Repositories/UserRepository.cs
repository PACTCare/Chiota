using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Services.Database.Base;

namespace Chiota.Services.Database.Repositories
{
    public class UserRepository : BaseRepository<User>
    {
        #region Constructors

        public UserRepository() : base()
        {
        }

        #endregion
    }
}
