#region

using System;
using System.Threading.Tasks;
using Chiota.Models.Database;
using Chiota.Resources.Localizations;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database.Base;
using Chiota.Services.Iota;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Contact;
using Pact.Palantir.Cache;
using Pact.Palantir.Encryption;
using Pact.Palantir.Entity;
using Pact.Palantir.Repository;
using Pact.Palantir.Service;
using Pact.Palantir.Usecase;
using Pact.Palantir.Usecase.AcceptContact;
using Pact.Palantir.Usecase.DeclineContact;
using SQLite;
using Tangle.Net.Cryptography.Signing;
using Tangle.Net.Entity;
using Xamarin.Forms;

#endregion

namespace Chiota.Services.BackgroundServices
{
    public class AnswerContactRequestBackgroundJob : BaseSecurityBackgroundJob
    {
        #region Attributes

        private INotification _notification;
        private SQLiteConnection _database;

        private TableMapping _contactTableMapping;

        private DbUser _user;
        private DbContact _contact;
        private bool _isAccepted;

        private static IMessenger Messenger => new TangleMessenger(new RepositoryFactory().Create(), new MemoryTransactionCache());
        private static IContactRepository ContactRepository => new MemoryContactRepository(Messenger, new SignatureValidator());
        private static AcceptContactInteractor AcceptInteractor => new AcceptContactInteractor(ContactRepository, Messenger, NtruEncryption.Key);
        private static DeclineContactInteractor DeclineInteractor => new DeclineContactInteractor(ContactRepository);

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
                    case DbContact contact:
                        _contact = contact;
                        break;
                    case bool isAccepted:
                        _isAccepted = isAccepted;
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
                if (_isAccepted)
                {
                    var response = await AcceptInteractor.ExecuteAsync(new AcceptContactRequest
                    {
                        UserName = _user.Name,
                        UserImagePath = _user.ImagePath,
                        ChatAddress = new Address(_contact.ChatAddress),
                        ChatKeyAddress = new Address(_contact.ChatKeyAddress),
                        ContactAddress = new Address(_contact.ContactAddress),
                        ContactPublicKeyAddress = new Address(_contact.PublicKeyAddress),
                        UserPublicKeyAddress = new Address(_user.PublicKeyAddress),
                        UserKeyPair = _user.NtruKeyPair,
                        UserContactAddress = new Address(_user.RequestAddress)
                    });

                    if (response.Code == ResponseCode.Success)
                    {
                        //Update the contact in the database.
                        var value = Encrypt(_contact.PublicKeyAddress);
                        var contact = _database.FindWithQuery(_contactTableMapping, "SELECT * FROM " + _contactTableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=?", value) as DbContact;

                        if (contact != null)
                        {
                            DecryptModel(contact);

                            _notification.Show(AppResources.NotifyAcceptedContactRequest, _contact.Name);

                            contact.Accepted = true;
                            EncryptModel(contact);
                            _database.Update(contact);
                        }
                    }
                    else
                        _notification.Show(AppResources.NotifyFailedAnswerContactRequest, _contact.Name);

                    MessagingCenter.Send(this, "AnswerContactRequest", response.Code);
                }
                else
                {
                    var response = await DeclineInteractor.ExecuteAsync(new DeclineContactRequest
                    {
                        ContactChatAddress = new Address(_contact.ChatAddress),
                        UserPublicKeyAddress = new Address(_user.PublicKeyAddress)
                    });

                    if (response.Code == ResponseCode.Success)
                    {
                        //Update the contact in the database.
                        var value = Encrypt(_contact.PublicKeyAddress);
                        var contact = _database.FindWithQuery(_contactTableMapping, "SELECT * FROM " + _contactTableMapping.TableName + " WHERE " + nameof(DbContact.PublicKeyAddress) + "=?", value) as DbContact;

                        if (contact != null)
                        {
                            DecryptModel(contact);

                            _notification.Show(AppResources.NotifyDeclinedContactRequest, _contact.Name);

                            //Update the contact in the database.
                            _database.Delete(contact.Id, _contactTableMapping);
                        }
                    }
                    else
                        _notification.Show(AppResources.NotifyFailedAnswerContactRequest, _contact.Name);

                    MessagingCenter.Send(this, "AnswerContactRequest", response.Code);
                }

                return false;
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
