#region References

using Chiota.Models.Database;
using System.Threading.Tasks;
using Chiota.Models;
using Tangle.Net.Entity;

#endregion

namespace Chiota.Services.UserServices
{


    /// <summary>
    /// The UserFactory interface.
    /// </summary>
    public interface IUserFactory
    {
        /// <summary>
        /// The create.
        /// </summary>
        /// <param name="seed">
        /// The seed.
        /// </param>
        /// <param name="name">
        /// The name.
        /// </param>
        /// <returns>
        /// The <see cref="DbUser"/>.
        /// </returns>
        Task<DbUser> CreateAsync(Seed seed, string name, string ImagePath, string imageBase64, EncryptionKey encryptionKey);
    }
}