#region References

using Newtonsoft.Json;

#endregion

namespace Chiota.Models
{
    public class EncryptionKey
    {
        #region Properties

        [JsonProperty("value")]
        public string Value { get; }

        [JsonProperty("salt")]
        public string Salt { get; }

        #endregion

        #region Constructors

        public EncryptionKey(string value, string salt)
        {
            Value = value;
            Salt = salt;
        }

        #endregion
    }
}
