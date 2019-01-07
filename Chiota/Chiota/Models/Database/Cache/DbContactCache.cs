#region References

using Chiota.Models.Database.Base;
using Newtonsoft.Json;

#endregion

namespace Chiota.Models.Database.Cache
{
    public class DbContactCache : BaseModel
    {
        #region Properties

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("accepted")]
        public bool Accepted { get; set; }

        #endregion
    }
}
