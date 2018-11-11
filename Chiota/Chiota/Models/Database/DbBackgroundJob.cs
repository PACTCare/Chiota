using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;

namespace Chiota.Models.Database
{
    public class DbBackgroundJob : TableModel
    {
        #region Properties

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("assembly")]
        public string Assembly { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("parameter")]
        public string Parameter { get; set; }

        #endregion
    }
}
