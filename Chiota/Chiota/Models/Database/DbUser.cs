using Chiota.Models.Database.Base;
using Newtonsoft.Json;
using SQLite;
using System.ComponentModel.DataAnnotations.Schema;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

namespace Chiota.Models.Database
{
    public class DbUser : TableModel
    {
        #region Properties

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("ImagePath")]
        public string ImagePath { get; set; }

        [JsonProperty("imagebase64")]
        public string ImageBase64 { get; set; }

        [JsonProperty("requestedaddress")]
        public string RequestAddress { get; set; }

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("storeseed")]
        public bool StoreSeed { get; set; }

        [JsonIgnore]
        [Ignore]
        public IAsymmetricKeyPair NtruKeyPair { get; set; }

        [JsonProperty("seed")]
        public string Seed { get; set; }

        [JsonProperty("encryptionkey")]
        [Ignore]
        public EncryptionKey EncryptionKey { get; set; }

        #endregion
    }
}
