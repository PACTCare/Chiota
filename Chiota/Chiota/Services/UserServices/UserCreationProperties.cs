#region References

using Tangle.Net.Entity;

#endregion

namespace Chiota.Services.UserServices
{
    public class UserCreationProperties
    {
        #region Properties

        public string Name { get; set; }

        public string Password { get; set; }

        public Seed Seed { get; set; }

        public string ImagePath { get; set; }

        public string ImageBase64 { get; set; }

        #endregion
    }
}