using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Tests.Presenters
{
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
        //var navigationStub = new NavigationStub();

        //var presenter = new AddContactPresenter(navigationStub);
        //await presenter.Present(new AddContactResponse { Code = code });
      }
    }
}
