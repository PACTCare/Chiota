#region References

using Chiota.Models.Database.Base;
using Newtonsoft.Json;

#endregion

namespace Chiota.Models.Database
{
    public class DbTransactionCache : BaseModel
    {
        [JsonProperty("transactionhash")]
        public string TransactionHash { get; set; }

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("messagetryte")]
        public string MessageTryte { get; set; }
    }
}
