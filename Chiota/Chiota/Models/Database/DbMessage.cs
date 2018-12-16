#region References

using System;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;

#endregion

namespace Chiota.Models.Database
{
    public class DbMessage : TableModel
    {
        #region Properties

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }

        [JsonProperty("date")]
        public DateTime Date { get; set; }

        [JsonProperty("signature")]
        public string Signature { get; set; }

        [JsonProperty("owner")]
        public bool Owner { get; set; }

        #endregion
    }
}
