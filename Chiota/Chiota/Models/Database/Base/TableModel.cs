using System.ComponentModel;
using System.Runtime.CompilerServices;
using Chiota.Annotations;
using Newtonsoft.Json;
using SQLite;

namespace Chiota.Models.Database.Base
{
    public abstract class TableModel : BaseModel
    {
        #region Properties

        [PrimaryKey, AutoIncrement]
        [JsonProperty("id")]
        public int Id { get; set; }

        #endregion
    }
}
