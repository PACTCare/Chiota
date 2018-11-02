using System;
using Chiota.Helper;
using Chiota.Models.Database;
using Xamarin.Forms;

namespace Chiota.Services.UserServices
{
    using System.Threading.Tasks;
  using Chiota.Models;

  using Pact.Palantir.Usecase;
  using Pact.Palantir.Usecase.CreateUser;

  using Tangle.Net.Entity;

    /// <inheritdoc />
    public class UserFactory : IUserFactory
    {
        public UserFactory(IUsecaseInteractor<CreateUserRequest, CreateUserResponse> createUserInteractor)
        {
            CreateUserInteractor = createUserInteractor;
        }

        private IUsecaseInteractor<CreateUserRequest, CreateUserResponse> CreateUserInteractor { get; }

        /// <inheritdoc />
        public async Task<DbUser> CreateAsync(Seed seed, string name, string imagePath, string imageBase64, EncryptionKey encryptionKey)
        {
            var response = await CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = seed });

            if (response.Code != ResponseCode.Success)
                return null;

            var user = new DbUser
            {
                Name = name,
                Seed = seed.Value,
                ImagePath = imagePath,
                ImageBase64 = imageBase64,
                StoreSeed = true,
                PublicKeyAddress = response.PublicKeyAddress.Value,
                RequestAddress = response.RequestAddress.Value,
                NtruKeyPair = response.NtruKeyPair,
                EncryptionKey = encryptionKey
            };

            return user;
        }
    }
}
