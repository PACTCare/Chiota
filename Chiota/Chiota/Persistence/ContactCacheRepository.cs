#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Base;
using Chiota.Extensions;
using Chiota.Models.Database.Cache;
using Chiota.Services.UserServices;
using Pact.Palantir.Entity;
using Pact.Palantir.Repository;
using Pact.Palantir.Service;
using Tangle.Net.Cryptography.Signing;

#endregion

namespace Chiota.Persistence
{
    public class ContactCacheRepository : AbstractTangleContactRepository
    {
        #region Constructors

        public ContactCacheRepository(IMessenger messenger, ISignatureValidator signatureValidator) : base(messenger, signatureValidator)
        {
        }

        #endregion

        #region Methods

        #region AddContact

        public override async Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
        {
            await Task.Run(() =>
            {
                var exist = AppBase.Database.ContactCache.GetContactCacheByPublicKeyAddress(publicKeyAddress);
                if(exist != null) return;

                var contact = new DbContactCache()
                {
                    ChatAddress = address,
                    PublicKeyAddress = publicKeyAddress,
                    Accepted = accepted
                };

                AppBase.Database.ContactCache.AddObject(contact);
            });
        }

        #endregion

        #region LoadContacts

        public override async Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var contacts = AppBase.Database.ContactCache.GetAcceptedContactCachesByPublicKeyAddress(publicKeyAddress);
                    contacts = contacts.DecryptObjectList(UserService.CurrentUser.EncryptionKey);
                    var list = new List<Contact>();

                    foreach (var item in contacts)
                    {
                        list.Add(new Contact()
                        {
                            ChatAddress = item.ChatAddress,
                            Rejected = !item.Accepted
                        });
                    }

                    return list;
                }
                catch (Exception)
                {
                    return new List<Contact>();
                }
            });
        }

        #endregion

        #endregion
    }
}
