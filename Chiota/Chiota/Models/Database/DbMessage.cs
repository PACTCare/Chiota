using Chiota.Models.Database.Base;
using Newtonsoft.Json;

namespace Chiota.Models.Database
{
    public class DbMessage : TableModel
    {
        #region Properties

        [JsonProperty("transactionhash")]
        public string TransactionHash { get; set; }

        [JsonProperty("chataddress")]
        public string ChatAddress { get; set; }

        [JsonProperty("messagetryte")]
        public string MessageTryte { get; set; }

        #endregion
    }
}
