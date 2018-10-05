using Chiota.Models.Database.Base;
using Newtonsoft.Json;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

namespace Chiota.Models.Database
{
    public class User : BaseModel
    {
        #region Properties

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("imagehash")]
        public string ImageHash { get; set; }

        [JsonProperty("requestedaddress")]
        public string RequestAddress { get; set; }

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("storeseed")]
        public bool StoreSeed { get; set; }

        [JsonIgnore]
        public IAsymmetricKeyPair NtruKeyPair { get; set; }

        [JsonProperty("seed")]
        public string Seed { get; set; }

        #endregion

        #region ForeignKeys

        #endregion
    }
}
