#region References

using Newtonsoft.Json;
using SQLite;

#endregion

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
