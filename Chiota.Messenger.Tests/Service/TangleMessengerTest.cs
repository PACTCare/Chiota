using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Messenger.Tests.Service
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Entity;
  using Chiota.Messenger.Exception;
  using Chiota.Messenger.Service;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  [TestClass]
    public class TangleMessengerTest
    {
      [TestMethod]
      [ExpectedException(typeof(UnknownMessageException))]
      public async Task TestMessageTypeIsUnkownShouldThrowException()
      {
        var messenger = new TangleMessenger(new InMemoryIotaRepository());
        await messenger.SendMessageAsync(new Message("SomeUnkownType", new TryteString(), new Address()));
      }

      [TestMethod]
      public async Task TestMessageIsValidShouldSendBundleWithTypeAndPayload()
      {
        var repository = new InMemoryIotaRepository();

        var messenger = new TangleMessenger(repository);
        var receiver = new Address("GUEOJUOWOWYEXYLZXNQUYMLMETF9OOGASSKUZZWUJNMSHLFLYIDIVKXKLTLZPMNNJCYVSRZABFKCAVVIW");
        await messenger.SendMessageAsync(new Message(MessageType.RequestContact, new TryteString(), receiver));

        Assert.AreEqual(1, repository.SentBundles.Count);

        var sentBundle = repository.SentBundles[0];

        Assert.AreEqual(receiver.Value, sentBundle.Transactions[0].Address.Value);
      }
    }
}
