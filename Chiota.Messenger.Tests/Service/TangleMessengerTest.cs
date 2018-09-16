namespace Chiota.Messenger.Tests.Service
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Service.Parser;
  using Chiota.Messenger.Tests.Cache;
  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

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
      public async Task TestMessagesGetLoadedFromTangle()
      {
        var repository = new InMemoryIotaRepository();

        var messenger = new TangleMessenger(repository, new InMemoryTransactionCache());

        var receiver = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
        var payload = TryteString.FromUtf8String("Hi. I'm a test").Concat(new TryteString(Constants.End.Value));

        await messenger.SendMessageAsync(new Message(payload, receiver));

        var sentMessages = await messenger.GetMessagesByAddressAsync(receiver, new RequestContactBundleParser());

        Assert.AreEqual("Hi. I'm a test", sentMessages[0].Payload.ToUtf8String());
      }
    }
}
