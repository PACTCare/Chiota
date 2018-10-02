namespace Chiota.Messenger.Tests.Service
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;
  using Chiota.Messenger.Tests.Cache;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Constants = Chiota.Messenger.Constants;

  [TestClass]
  public class TangleMessengerTest
  {
    [TestMethod]
    public async Task TestIotaRepositoryThrowsExceptionShouldSetAsInnerExceptionAndRethrowExceptionWithErrorCode()
    {
      var exceptionThrown = false;

      try
      {
        var messenger = new TangleMessenger(new ExceptionIotaRepository(), new InMemoryTransactionCache());
        await messenger.SendMessageAsync(new Message(new TryteString(), new Address()));
      }
      catch (Exception exception)
      {
        exceptionThrown = true;

        Assert.IsInstanceOfType(exception, typeof(MessengerException));
        Assert.AreEqual(ResponseCode.MessengerException, ((MessengerException)exception).Code);
      }

      Assert.IsTrue(exceptionThrown);
    }

    [TestMethod]
    public async Task TestMessageIsValidShouldSendBundleWithTypeAndPayload()
    {
      var repository = new InMemoryIotaRepository();

      var messenger = new TangleMessenger(repository, new InMemoryTransactionCache());
      var receiver = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var payload = new TryteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
      await messenger.SendMessageAsync(new Message(payload, receiver));

      Assert.AreEqual(1, repository.SentBundles.Count);

      var sentBundle = repository.SentBundles[0];
      Assert.AreEqual(receiver.Value, sentBundle.Transactions[0].Address.Value);
      Assert.AreEqual(payload.Value, sentBundle.Transactions[0].Fragment.GetChunk(0, payload.TrytesLength).Value);
    }

    [TestMethod]
    public async Task TestTransactionIsCachedShouldMergeWithMessagesFromTangle()
    {
      var repository = new InMemoryIotaRepository();
      var transactionCache = new InMemoryTransactionCache();

      var messenger = new TangleMessenger(repository, transactionCache);

      var receiver = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
      var payload = TryteString.FromUtf8String("Hi. I'm a test").Concat(new TryteString(Constants.End.Value));

      var messageOne = new Message(payload, receiver);
      var bundle = new Bundle();
      bundle.AddTransfer(
        new Transfer
          {
            Address = messageOne.Receiver, Message = messageOne.Payload, Tag = Constants.Tag, Timestamp = Timestamp.UnixSecondsTimestamp
          });

      bundle.Finalize();
      bundle.Sign();
      await repository.SendTrytesAsync(bundle.Transactions);
      await transactionCache.SaveTransactionAsync(
        new TransactionCacheItem
          {
            Address = receiver,
            TransactionHash = new Hash(Seed.Random().Value),
            TransactionTrytes = new TransactionTrytes(TryteString.FromUtf8String("Hi. I'm a test").Concat(Constants.End).Value)
          });

      var sentMessages = await messenger.GetMessagesByAddressAsync(receiver, new MessageBundleParser());

      Assert.AreEqual(2, sentMessages.Count);
      Assert.AreEqual("Hi. I'm a test", sentMessages[0].Payload.ToUtf8String());
      Assert.AreEqual("Hi. I'm a test", sentMessages[1].Payload.ToUtf8String());
    }
  }
}