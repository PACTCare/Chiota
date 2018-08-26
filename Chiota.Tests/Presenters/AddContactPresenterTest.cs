namespace Chiota.Tests.Presenters
{
  using System;
  using System.Threading.Tasks;

  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Presenters;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  [TestClass]
    public class AddContactPresenterTest
    {
      [DataTestMethod]
      [DataRow(ResponseCode.Success, "Successful Request", "Your new contact needs to accept the request before you can start chatting!.")]
      public async Task TestErrorCodesMapToDesiredTranslationsAndDisplayPopup(ResponseCode code, string title, string text)
      {
        // TODO: Navigation needs to be implemented without extensions to enable presenters to be tested
        throw new NotImplementedException(); 
        var navigationStub = new NavigationStub();

        var presenter = new AddContactPresenter(navigationStub);
        await presenter.Present(new AddContactResponse { Code = code });
    }
    }
}
