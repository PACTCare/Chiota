using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Chiota.Messenger.Cache;
using Chiota.Models.Database;
using Chiota.Services.Database;
using Tangle.Net.Entity;

namespace Chiota.Persistence
{
    public class MessageRepository : ITransactionCache
    {
        #region Methods

        #region Flush

        public async Task FlushAsync()
        {
            DatabaseService.Message.DeleteObjects();
        }

        #endregion

        #region SaveTransaction

        public async Task SaveTransactionAsync(TransactionCacheItem item)
        {
            var message = new DbMessage()
            {
                TransactionHash = item.TransactionHash.Value,
                ChatAddress = item.Address.Value,
                MessageTryte = item.TransactionTrytes.Value
            };
            DatabaseService.Message.AddObject(message);
        }

        #endregion

        #region LoadTransactionsByAddress

        public async Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
        {
            var messages = DatabaseService.Message.GetMessagesByChatAddress(address.Value);

            var list = new List<TransactionCacheItem>();

            foreach (var item in messages)
            {
                list.Add(new TransactionCacheItem()
                {
                    Address = new Address(item.ChatAddress),
                    TransactionHash = new Hash(item.TransactionHash),
                    TransactionTrytes = new TransactionTrytes(item.MessageTryte)
                });
            }

            return list;
        }

        #endregion

        #endregion
    }
}
