namespace Chiota.Tests.Presenters
{
  using System.Collections.Generic;

  using Chiota.Models;
  using Chiota.Presenters;
  using Chiota.Services.DependencyInjection;
  using Chiota.Tests.DependencyInjection;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Pact.Palantir.Entity;
  using Pact.Palantir.Usecase;
  using Pact.Palantir.Usecase.GetContacts;

  using Tangle.Net.Entity;

  /// <summary>
  /// The get contacts presenter test.
  /// </summary>
  [TestClass]
  public class GetContactsPresenterTest
  {
    [TestInitialize]
    public void Init()
    {
      DependencyResolver.Modules.Add(new FakeModule());
      DependencyResolver.Init();
    }

    /// <summary>
    /// The test response contacts get mapped to view model without search.
    /// </summary>
    [TestMethod]
    public void TestResponseContactsGetMappedToViewModelWithoutSearch()
    {
      var response = new GetContactsResponse
                       {
                         Code = ResponseCode.Success,
                         ApprovedContacts =
                           new List<Contact>
                             {
                               new Contact { ChatAddress = Hash.Empty.Value, Request = false, Rejected = false }
                             },
                         PendingContactRequests =
                           new List<Contact>
                             {
                               new Contact { ChatAddress = Hash.Empty.Value, Request = true, Rejected = false }
                             }
                       };

      var viewModels = GetContactsPresenter.Present(response, new ViewCellObject());

      Assert.AreEqual(2, viewModels.Count);
    }

    [TestMethod]
    public void TestResponseShouldBeFilteredBySearch()
    {
      var response = new GetContactsResponse
                       {
                         Code = ResponseCode.Success,
                         ApprovedContacts =
                           new List<Contact>
                             {
                               new Contact
                                 {
                                   ChatAddress = Hash.Empty.Value,
                                   Request = false,
                                   Rejected = false,
                                   Name = "hans"
                                 }
                             },
                         PendingContactRequests =
                           new List<Contact>
                             {
                               new Contact
                                 {
                                   ChatAddress = Hash.Empty.Value,
                                   Request = true,
                                   Rejected = false,
                                   Name = "Peter"
                                 }
                             }
                       };

      var viewModels = GetContactsPresenter.Present(response, new ViewCellObject(), "Hans");

      Assert.AreEqual(1, viewModels.Count);
    }
  }
}