namespace Chiota.Services.UserServices
{
    using Tangle.Net.Entity;

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