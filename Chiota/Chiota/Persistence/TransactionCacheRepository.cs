#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Base;
using Chiota.Models.Database;
using Chiota.Models.Database.Cache;
using Pact.Palantir.Cache;
using Tangle.Net.Entity;

#endregion

namespace Chiota.Persistence
{
    public class TransactionCacheRepository : ITransactionCache
    {
        #region Methods

        #region Flush

        public async Task FlushAsync()
        {
            await Task.Run(() =>
            {
                AppBase.Database.TransactionCache.DeleteObjects();
            });
        }

        #endregion

        #region SaveTransaction

        public async Task SaveTransactionAsync(TransactionCacheItem item)
        {
            await Task.Run(() =>
            {
                var transactionCache = new DbTransactionCache()
                {
                    TransactionHash = item.TransactionHash.Value,
                    ChatAddress = item.Address.Value,
                    MessageTryte = item.TransactionTrytes.Value
                };
                AppBase.Database.TransactionCache.AddObject(transactionCache);
            });
        }

        #endregion

        #region LoadTransactionsByAddress

        public async Task<List<TransactionCacheItem>> LoadTransactionsByAddressAsync(Address address)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var transactionCache = AppBase.Database.TransactionCache.GetTransactionCacheByChatAddress(address.Value);
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
        }

        #endregion

        #endregion
    }
}
