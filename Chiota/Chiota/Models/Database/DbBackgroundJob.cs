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

        [JsonProperty("parameter")]
        public string Parameter { get; set; }

        #endregion
    }
}
