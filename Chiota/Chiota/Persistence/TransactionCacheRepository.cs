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
    public class TransactionCacheRepository : ITransactionCache
    {
        #region Methods

        #region Flush

        public Task FlushAsync()
        {
            var task = Task.Run(() =>
            {
                DatabaseService.TransactionCache.DeleteObjects();
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
                var transactionCache = new DbTransactionCache()
                {
                    TransactionHash = item.TransactionHash.Value,
                    ChatAddress = item.Address.Value,
                    MessageTryte = item.TransactionTrytes.Value
                };
                DatabaseService.TransactionCache.AddObject(transactionCache);
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
                    var transactionCache = DatabaseService.TransactionCache.GetTransactionCacheByChatAddress(address.Value);

                    var list = new List<TransactionCacheItem>();

                    foreach (var item in transactionCache)
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
