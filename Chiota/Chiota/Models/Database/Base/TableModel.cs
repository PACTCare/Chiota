using System.ComponentModel;
using System.Runtime.CompilerServices;
using Chiota.Annotations;

namespace Chiota.Models.Database.Base
{
    public abstract class TableModel : BaseModel
    {
        #region Properties

        public int Id { get; set; }

        #endregion
    }
}
