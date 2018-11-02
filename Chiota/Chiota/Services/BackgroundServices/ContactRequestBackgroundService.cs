using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Extensions;
using Chiota.Models.Database;
using Chiota.Persistence;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.BackgroundServices.Trigger;
using Chiota.Services.Database;
using Chiota.Services.Database.Base;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Pact.Palantir.Cache;
using Pact.Palantir.Encryption;
using Pact.Palantir.Repository;
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.AddContact;
using Pact.Palantir.Usecase.GetContacts;
using SQLite;
using Tangle.Net.Cryptography.Signing;
using Tangle.Net.Entity;
using Tangle.Net.Repository;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using Xamarin.Forms;

namespace Chiota.Services.BackgroundServices
{
    public class ContactRequestBackgroundService : BaseBackgroundService
    {
        #region Attributes

        private SQLiteConnection _connection;

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static IContactRepository ContactRepository => new MemoryContactRepository(Messenger, new SignatureValidator());
        private static GetContactsInteractor Interactor => new GetContactsInteractor(ContactRepository, Messenger, NtruEncryption.Key);

        private DbUser User;

        #endregion

        #region Constructors

        public ContactRequestBackgroundService()
        {
            Name = "Chiota.ContactRequest";

            //Set the triggers and conditions.
            Triggers.Add(new TimeTrigger(TimeSpan.FromMinutes(3)));
            Conditions.Add(ConditionType.InternetAvailable);
        }

        #endregion

        #region Methods

        #region Init

        public override void Init(params object[] objects)
        {
            base.Init(objects);

            //Get the sqlite database connection.
            _connection = DependencyService.Get<ISqlite>().GetDatabaseConnection();

            if (objects[0] is DbUser user)
                User = user;
        }

        #endregion

        #region Run

        public override async Task RunAsync()
        {
            try
            {
                //Execute a contacts request for the user.
                var response = await Interactor.ExecuteAsync(
                    new GetContactsRequest
                    {
                        RequestAddress = new Address(User.RequestAddress),
                        PublicKeyAddress = new Address(User.PublicKeyAddress),
                        KeyPair = User.NtruKeyPair
                    });

                if (response.PendingContactRequests.Count <= 0) return;

                var pendingContacts = DatabaseService.Contact.GetPendingContacts().DecryptObjectList(User.EncryptionKey);
                foreach (var item in response.PendingContactRequests)
                {
                    var existInDatabase = pendingContacts.Find(t => t.PublicKeyAddress == item.PublicKeyAddress);
                    if (existInDatabase == null)
                    {
                        //Add the new contact request to the database and show a notification.
                        var request = new DbContact()
                        {
                            Name = item.Name,
                            ImagePath = item.ImagePath,
                            ChatKeyAddress = item.ChatKeyAddress,
                            ChatAddress = item.ChatAddress,
                            PublicKeyAddress = item.PublicKeyAddress,
                            Accepted = !item.Rejected
                        };

                        DependencyService.Get<INotification>().Show("New contact request", request.Name);
                        DatabaseService.Contact.AddObject(request.EncryptObject(User.EncryptionKey));
                    }
                }
            }
            catch (Exception)
            {
                //Ignore
            }
        }

        #endregion

        #endregion
    }
}
