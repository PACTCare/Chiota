namespace Chiota.Tests.Presenters
{
  using System;
  using System.Threading.Tasks;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Pact.Palantir.Usecase;

  [TestClass]
    public class AddContactPresenterTest
    {
      [DataTestMethod]
      [DataRow(ResponseCode.Success, "Successful Request", "Your new contact needs to accept the request before you can start chatting!.")]
      public async Task TestErrorCodesMapToDesiredTranslationsAndDisplayPopup(ResponseCode code, string title, string text)
      {
        // TODO: Navigation needs to be implemented without extensions to enable presenters to be tested
        throw new NotImplementedException(); 
        //var navigationStub = new NavigationStub();

        //await AddContactPresenter.Present(navigationStub, new AddContactResponse { Code = code });
    }
    }
}
