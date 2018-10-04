using Chiota.Messenger.Entity;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Messenger.Usecase;
using Chiota.Messenger.Usecase.GetMessages;
using Chiota.Models;
using Chiota.Services.DependencyInjection;
using Tangle.Net.Entity;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using System.Linq;
using Chiota.Controls.InfiniteScrolling;

namespace Chiota.Services.MessageServices
{
    public class MessageService
    {
        private string[] AllMessages = new string[]
        {
            "1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32",
            "33","34","35","36","37","38","39","40","41","42","43","44","45","46","47","48","49","50","51","52","53","54","55","56","57","58","59","60","61","62","63","64",
            "65","66","67","68","69","70","71","72","73","74","75","76","77","78","79","80","81","82","83","84","85","86","87","88","89","90","91","92","93","94","95","96",
            "97","98","99","100","101","102","103","104","105","106","107","108","109","110","111","112","113","114","115","116","117","118","119","120","121","122","123","124","125","126","127","128",
            "129","130","131","132","133","134","135","136","137","138"
        };

        #region GetMessagesAsync

        public async Task<List<MessageBinding>> GetMessagesAsync(Contact contact, IAsymmetricKeyPair keyPair, int pageIndex, int pageSize)
        {
            /*var messagesResponse = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(new GetMessagesRequest
            {
                ChatAddress = new Address(contact.ChatAddress),
                ChatKeyPair = keyPair
            });*/

            var messages = new List<MessageBinding>();
            foreach (var message in AllMessages)
            {
                //var isOwner = message.Signature != contact.PublicKeyAddress.Substring(0, 30);
                messages.Add(new MessageBinding(message, true));
            }

            var messagesCount = AllMessages.Count();
            var maxIndex = (messagesCount / pageSize) - 1;
            var rest = messagesCount % pageSize;

            if (rest > 0)
                maxIndex++;

            /*if (pageIndex == maxIndex)
                return messages.Take(rest).ToList();
            else
                return messages.Skip((((maxIndex - 1) - pageIndex) * pageSize) + rest).Take(pageSize).ToList<List<MessageBinding>>.Reverse<List<MessageBinding>>();*/

            return null;
        }

        public async Task<int> GetMessagesCountAsync(Contact contact, IAsymmetricKeyPair keyPair)
        {
            /*var messagesResponse = await DependencyResolver.Resolve<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>().ExecuteAsync(new GetMessagesRequest
            {
                ChatAddress = new Address(contact.ChatAddress),
                ChatKeyPair = keyPair
            });*/

            return AllMessages.Count();
        }

        #endregion
    }
}
