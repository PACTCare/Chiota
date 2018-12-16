#region References

using System.Threading.Tasks;
using Chiota.Models;
using Chiota.Models.Database;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.CreateUser;
using Tangle.Net.Entity;

#endregion

namespace Chiota.Services.UserServices
{
    /// <inheritdoc />
    public class UserFactory : IUserFactory
    {
        public UserFactory(IUsecaseInteractor<CreateUserRequest, CreateUserResponse> createUserInteractor)
        {
            this.CreateUserInteractor = createUserInteractor;
        }

        private IUsecaseInteractor<CreateUserRequest, CreateUserResponse> CreateUserInteractor { get; }

        /// <inheritdoc />
        public async Task<DbUser> CreateAsync(Seed seed, string name, string imagePath, string imageBase64, EncryptionKey encryptionKey)
        {
            var response = await this.CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = seed });

            if (response.Code != ResponseCode.Success)
            {
                return null;
            }

            return new DbUser
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
        }
    }
}