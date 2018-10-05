using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;

namespace Chiota.Services.Database.Base
{
    public class DatabaseInfo : BaseModel
    {
        #region Properties

        [JsonProperty("userstored")]
        public bool UserStored { get; set; }

        #endregion
    }
}
