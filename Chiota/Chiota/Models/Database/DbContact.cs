using Chiota.Models.Database.Base;
using Newtonsoft.Json;

namespace Chiota.Models.Database
{
    public class DbContacts : TableModel
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
