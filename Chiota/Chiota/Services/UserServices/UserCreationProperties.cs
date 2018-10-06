namespace Chiota.Services.UserServices
{
    using Tangle.Net.Entity;

    public class UserCreationProperties
    {
        #region Properties

        public string Name { get; set; }

        public string Password { get; set; }

        public Seed Seed { get; set; }

        public string ImageHash { get; set; }

        public string ImageBase64 { get; set; }

        #endregion
    }
}