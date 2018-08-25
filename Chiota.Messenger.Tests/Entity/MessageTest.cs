namespace Chiota.Messenger.Tests.Entity
{
  using Chiota.Messenger.Entity;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  /// <summary>
  /// The message test.
  /// </summary>
  [TestClass]
  public class MessageTest
  {
    /// <summary>
    /// The test message type does not exist should be invalid.
    /// </summary>
    [TestMethod]
    public void TestMessageTypeDoesNotExistShouldBeMarkedAsUnkown()
    {
      var message = new Message("UnknownType", new TryteString(), new Address());
      Assert.IsFalse(message.HasKnownType);
    }

    [TestMethod]
    public void TestMessageTypeDoesExistShouldBeMarkedAsKown()
    {
      var message = new Message(MessageType.RequestContact, new TryteString(), new Address());
      Assert.IsTrue(message.HasKnownType);
    }
  }
}