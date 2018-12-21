#region References

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Models;
using Chiota.Models.Database;
using Chiota.Models.Database.Base;
using Chiota.Resources.Localizations;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using Chiota.Services.Iota;
using Chiota.Services.Security;
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

#endregion

namespace Chiota.Services.BackgroundServices
{
    public class ContactRequestBackgroundJob : BaseSecurityBackgroundJob
    {
        #region Attributes

        private INotification _notification;
        private SQLiteConnection _database;

        private TableMapping _contactTableMapping;

        private DbUser _user;

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static IContactRepository ContactRepository => new MemoryContactRepository(Messenger, new SignatureValidator());
        private static GetContactsInteractor Interactor => new GetContactsInteractor(ContactRepository, Messenger, NtruEncryption.Key);

        #endregion

        #region Methods

        #region Init

        public override void Init(params object[] data)
        {
            base.Init(data);

            //Init the notification interface.
            _notification = DependencyService.Get<INotification>();
            _database = DependencyService.Get<ISqlite>().GetDatabaseConnection();

            _contactTableMapping = new TableMapping(typeof(DbContact));

            if (data.Length == 0) return;

            foreach (var item in data)
            {
                switch (item)
                {
                    case DbUser user:
                        _user = user;
                        _user.NtruKeyPair = NtruEncryption.Key.CreateAsymmetricKeyPair(_user.Seed.ToLower(), _user.PublicKeyAddress);
                        break;
                }
            }
        }

        #endregion

        #region Run

        public override async Task<bool> RunAsync()
        {
            try
            {
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
                    //Handle contact requests for the user.
                    await Task.Run(() =>
                    {
                        if (response.PendingContactRequests == null ||
                            response.PendingContactRequests.Count == 0) return;

                        foreach (var item in response.PendingContactRequests)
                        {
                            if (item.Rejected) continue;

                            //Get the contact by public key address.
                            var value = Encrypt(item.PublicKeyAddress);
                            var contact = _database.FindWithQuery(_contactTableMapping, "SELECT * FROM " + _contactTableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=?", value) as DbContact;

                            if (contact == null)
                            {
                                //Add the new contact request to the database and show a notification.
                                var request = new DbContact()
                                {
                                    Name = item.Name,
                                    ImagePath = item.ImagePath,
                                    ContactAddress = item.ContactAddress,
                                    PublicKeyAddress = item.PublicKeyAddress,
                                    ChatKeyAddress = item.ChatKeyAddress,
                                    ChatAddress = item.ChatAddress,
                                    Accepted = false
                                };

                                _notification.Show(AppResources.NotifyNewContactRequest, item.Name);

                                //Add the contact and chat for the contact as an object into the database.
                                EncryptModel(request);
                                _database.Insert(request);
                            }
                        }
                    });

                    //Update the contacts of the user.
                    await Task.Run(() =>
                    {
                        //This shoud normally Accepted, not pending BUG in Palantir
                        if (response.PendingContactRequests == null ||
                            response.PendingContactRequests.Count == 0) return;

                        foreach (var item in response.PendingContactRequests)
                        {
                            //Get the contact by public key address.
                            var value = Encrypt(item.PublicKeyAddress);
                            var contact = _database.FindWithQuery(_contactTableMapping, "SELECT * FROM " + _contactTableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=?", value) as DbContact;
                            DecryptModel(contact);

                            if (contact != null && contact.Name == null && contact.ChatKeyAddress == null && contact.ContactAddress == null)
                            {
                                DecryptModel(contact);

                                //Update the new contact request to the database and show a notification.
                                contact.Name = item.Name;
                                contact.ImagePath = item.ImagePath;
                                contact.ChatKeyAddress = item.ChatKeyAddress;
                                contact.ChatAddress = item.ChatAddress;
                                contact.ContactAddress = item.ContactAddress;
                                contact.PublicKeyAddress = item.PublicKeyAddress;
                                contact.Accepted = !item.Rejected;

                                _notification.Show(AppResources.NotifyNewContact, contact.Name);

                                //Update the object in the database.
                                EncryptModel(contact);
                                _database.Update(contact);
                            }
                        }
                    });

                    return true;
                }
                return true;
            }
            catch (Exception)
            {
                //Ignore
                return true;
            }
        }

        #endregion

        #endregion
    }
}
