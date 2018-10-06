using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using Chiota.Annotations;
using Newtonsoft.Json;

namespace Chiota.Models.Database.Base
{
    public abstract class TableModel : BaseModel
    {
        #region Properties

        [Key]
        [JsonProperty("id")]
        public int Id { get; set; }

        #endregion
    }
}
