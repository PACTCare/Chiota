using System.ComponentModel.DataAnnotations.Schema;
using Chiota.Models.Database.Base;
using Newtonsoft.Json;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;

namespace Chiota.Models.Database
{
    public class DbUser : TableModel
    {
        #region Properties

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("imagehash")]
        public string ImageHash { get; set; }

        [JsonProperty("imagebase64")]
        public string ImageBase64 { get; set; }

        [JsonProperty("requestedaddress")]
        public string RequestAddress { get; set; }

        [JsonProperty("publickeyaddress")]
        public string PublicKeyAddress { get; set; }

        [JsonProperty("storeseed")]
        public bool StoreSeed { get; set; }

        [JsonIgnore]
        [NotMapped]
        public IAsymmetricKeyPair NtruKeyPair { get; set; }

        [JsonProperty("seed")]
        public string Seed { get; set; }

        #endregion

        #region ForeignKeys

        #endregion

        #region Constructors

        public DbUser()
        {

        }

        public DbUser(DbUser user)
        {
            Id = user.Id;
            Name = user.Name;
            ImageHash = user.ImageHash;
            ImageBase64 = user.ImageBase64;
            RequestAddress = user.RequestAddress;
            PublicKeyAddress = user.PublicKeyAddress;
            StoreSeed = user.StoreSeed;
            NtruKeyPair = user.NtruKeyPair;
            Seed = user.Seed;
        }

        #endregion
    }
}
