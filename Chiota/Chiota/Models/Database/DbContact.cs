using Chiota.Models.Database.Base;
using Newtonsoft.Json;

namespace Chiota.Models.Database
{
    public class DbContact : TableModel
    {
        #region Properties

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("ImagePath")]
        public string ImagePath { get; set; }

        [JsonProperty("imagebase64")]
        public string ImageBase64 { get; set; }

        [JsonProperty("chatkeyaddress")]
        public string ChatKeyAddress { get; set; }

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("accepted")]
        public bool Accepted { get; set; }

        #endregion
    }
}
