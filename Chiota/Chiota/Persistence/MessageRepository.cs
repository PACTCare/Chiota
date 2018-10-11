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

        public Task FlushAsync()
        {
            var task = Task.Run(() =>
            {
                DatabaseService.Message.DeleteObjects();
            });
            task.Wait();

            return task;
        }

        #endregion

        #region SaveTransaction

        public Task SaveTransactionAsync(TransactionCacheItem item)
        {
            var task = Task.Run(() =>
            {
                var message = new DbMessage()
                {
                    TransactionHash = item.TransactionHash.Value,
                    ChatAddress = item.Address.Value,
                    MessageTryte = item.TransactionTrytes.Value
                };
                DatabaseService.Message.AddObject(message);
            });
            task.Wait();

            return task;
        }

        #endregion

        #region LoadTransactionsByAddress

        public Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
        {
            var task = Task.Run(() =>
            {
                try
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
                catch (Exception)
                {
                    return new List<TransactionCacheItem>();
                }
            });
            task.Wait();

            return task;
        }

        #endregion

        #endregion
    }
}
