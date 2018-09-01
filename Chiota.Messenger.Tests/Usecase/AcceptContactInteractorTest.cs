namespace Chiota.Messenger.Tests.Usecase
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Tests.Repository;
  using Chiota.Messenger.Tests.Service;
  using Chiota.Messenger.Usecase.AcceptContact;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  /// <summary>
  /// The accept contact interactor test.
  /// </summary>
  [TestClass]
  public class AcceptContactInteractorTest
  {
    [TestMethod]
    public async Task TestAcceptedContactShouldBeAddedToRepository()
    {
      var interactor = new AcceptContactInteractor(new InMemoryContactRepository(), new InMemoryMessenger());
      var response = await interactor.ExecuteAsync(new AcceptContactRequest());
    }
  }
}