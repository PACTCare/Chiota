#region References

using System;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;
using SQLiteNetExtensions.Attributes;

#endregion

namespace Chiota.Models.Database
{
    public class DbMessage : BaseModel
    {
        #region Properties

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("chatkeyaddress")]
        public string ChatKeyAddress { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }

        [JsonProperty("date")]
        public DateTime Date { get; set; }

        [JsonProperty("status")]
        public int Status { get; set; }

        [JsonProperty("signature")]
        public string Signature { get; set; }

        [JsonProperty("owner")]
        public bool Owner { get; set; }

        #endregion

        #region ForeignKeys

        [ForeignKey(typeof(DbContact))]
        public int ContactId { get; set; }

        #endregion
    }

    public enum MessageStatus
    {
        Written = 0,
        Send = 1,
        Received = 2,
        Read = 3,
        Failed = 4
    }
}
