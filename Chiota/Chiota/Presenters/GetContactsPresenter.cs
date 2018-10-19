namespace Chiota.Presenters
{
  using System.Collections.Generic;
  using System.Linq;

  using Chiota.Models;
  using Chiota.Services.DependencyInjection;
  using Chiota.ViewModels;

  using Pact.Palantir.Usecase;
  using Pact.Palantir.Usecase.AcceptContact;
  using Pact.Palantir.Usecase.DeclineContact;
  using Pact.Palantir.Usecase.GetContacts;

  /// <summary>
  /// The get contacts presenter.
  /// </summary>
  public static class GetContactsPresenter
  {
    /// <summary>
    /// The present.
    /// </summary>
    /// <param name="response">
    /// The response.
    /// </param>
    /// <param name="viewCell">
    /// The view cell.
    /// </param>
    /// <param name="searchContactsBy">
    /// The search contacts by.
    /// </param>
    /// <returns>
    /// The <see cref="List"/>.
    /// </returns>
    public static List<ContactListViewModel> Present(GetContactsResponse response, ViewCellObject viewCell, string searchContactsBy = null)
    {
      var result = new List<ContactListViewModel>();

      var acceptContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse>>();
      var declineContactInteractor = DependencyResolver.Resolve<IUsecaseInteractor<DeclineContactRequest, DeclineContactResponse>>();

      result.AddRange(
        response.ApprovedContacts.Select(c => new ContactListViewModel(acceptContactInteractor, declineContactInteractor, viewCell, c)));
      result.AddRange(
        response.PendingContactRequests.Select(c => new ContactListViewModel(acceptContactInteractor, declineContactInteractor, viewCell, c)));

      if (!string.IsNullOrEmpty(searchContactsBy))
      {
        return result.Where(c => c.Contact.Name.ToLower().StartsWith(searchContactsBy.ToLower())).ToList();
      }

      return result;
    }
  }
}