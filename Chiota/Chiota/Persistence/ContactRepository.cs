using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Messenger.Entity;
using Chiota.Messenger.Repository;
using Chiota.Messenger.Service;
using Chiota.Models.Database;
using Chiota.Services.Database;
using Tangle.Net.Cryptography.Signing;

namespace Chiota.Persistence
{
    public class ContactRepository : AbstractTangleContactRepository
    {
        #region Constructors

        public ContactRepository(IMessenger messenger, ISignatureValidator signatureValidator) : base(messenger, signatureValidator)
        {
        }

        #endregion

        #region Methods

        #region AddContact

        public override async Task AddContactAsync(string address, bool accepted, string publicKeyAddress)
        {
            var contact = new DbContact()
            {
                ChatAddress = address,
                PublicKeyAddress = publicKeyAddress,
                Accepted = accepted
            };

            DatabaseService.Contact.AddObject(contact);
        }

        #endregion

        #region LoadContacts

        public override async Task<List<Contact>> LoadContactsAsync(string publicKeyAddress)
        {
            var contacts = DatabaseService.Contact.GetAcceptedContactsByPublicKeyAddress(publicKeyAddress);
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

        #endregion

        #endregion
    }
}
