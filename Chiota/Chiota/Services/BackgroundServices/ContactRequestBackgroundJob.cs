using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Extensions;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using Chiota.Services.Iota;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Pact.Palantir.Cache;
using Pact.Palantir.Encryption;
using Pact.Palantir.Repository;
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.GetContacts;
using SQLite;
using Tangle.Net.Cryptography.Signing;
using Tangle.Net.Entity;
using Xamarin.Forms;

namespace Chiota.Services.BackgroundServices
{
    public class ContactRequestBackgroundJob : BaseBackgroundJob
    {
        #region Attributes

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static IContactRepository ContactRepository => new MemoryContactRepository(Messenger, new SignatureValidator());
        private static GetContactsInteractor Interactor => new GetContactsInteractor(ContactRepository, Messenger, NtruEncryption.Key);

        private DbUser _user;

        #endregion

        #region Constructors

        public ContactRequestBackgroundJob(DatabaseService database, INotification notification) : base(database, notification)
        {
        }

        #endregion

        #region Methods

        #region Init

        public override void Init(string data = null)
        {
            base.Init(data);

            if (string.IsNullOrEmpty(data)) return;
            var json = JArray.Parse(data);
            _user = JsonConvert.DeserializeObject<DbUser>(JsonConvert.SerializeObject(json[0]));
            _user.NtruKeyPair = NtruEncryption.Key.CreateAsymmetricKeyPair(_user.Seed.ToLower(), _user.PublicKeyAddress);
        }

        #endregion

        #region Run

        public override async Task<bool> RunAsync()
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1));

                //Execute a contacts request for the user.
                var response = await Interactor.ExecuteAsync(
                    new GetContactsRequest
                    {
                        RequestAddress = new Address(_user.RequestAddress),
                        PublicKeyAddress = new Address(_user.PublicKeyAddress),
                        KeyPair = _user.NtruKeyPair
                    });

                if (response.Code == ResponseCode.Success)
                {
                    if (response.PendingContactRequests.Count <= 0) return true;

                    foreach (var item in response.PendingContactRequests)
                    {
                        if (item.Rejected) continue;

                        var contact = Database.Contact.GetContactByPublicKeyAddress(item.PublicKeyAddress.EncryptValue(_user.EncryptionKey));
                        if (contact == null)
                        {
                            //Add the new contact request to the database and show a notification.
                            var request = new DbContact()
                            {
                                Name = item.Name,
                                ImagePath = item.ImagePath,
                                ChatKeyAddress = item.ChatKeyAddress,
                                ChatAddress = item.ChatAddress,
                                PublicKeyAddress = item.PublicKeyAddress,
                                Accepted = false
                            };

                            DependencyService.Get<INotification>().Show("New contact request", request.Name);
                            Database.Contact.AddObject(request.EncryptObject(_user.EncryptionKey));
                        }
                    }

                    return true;
                }
                return false;
            }
            catch (Exception)
            {
                //Ignore
                return false;
            }
        }

        #endregion

        #endregion
    }
}
