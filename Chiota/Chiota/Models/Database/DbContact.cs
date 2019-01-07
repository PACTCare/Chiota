#region References

using System.Collections.Generic;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;
using SQLiteNetExtensions.Attributes;

#endregion

namespace Chiota.Models.Database
{
    public class DbContact : BaseModel
    {
        #region Properties

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("imagepath")]
        public string ImagePath { get; set; }

        [JsonProperty("imagebase64")]
        public string ImageBase64 { get; set; }

        [JsonProperty("chatkeyaddress")]
        public string ChatKeyAddress { get; set; }

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("currentchataddress")]
        public string CurrentChatAddress { get; set; }

        [JsonProperty("contactaddress")]
        public string ContactAddress { get; set; }

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("accepted")]
        public bool Accepted { get; set; }

        #endregion

        #region ForeignKeys

        [ForeignKey(typeof(DbUser))]
        public int UserId { get; set; }

        [JsonProperty("messages")]
        [OneToMany]
        public List<DbMessage> Messages { get; set; }

        #endregion
    }
}
