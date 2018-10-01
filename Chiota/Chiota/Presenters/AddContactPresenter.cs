namespace Chiota.Presenters
{
  using System.Threading.Tasks;

  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.ViewModels.Classes;

  /// <summary>
  /// The add contact presenter.
  /// </summary>
  public static class AddContactPresenter
  {
    /// <summary>
    /// The present.
    /// </summary>
    /// <param name="view">
    /// The view.
    /// </param>
    /// <param name="response">
    /// The response.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public static async Task Present(BaseViewModel view, AddContactResponse response)
    {
      switch (response.Code)
      {
        case ResponseCode.Success:
          await view.DisplayAlertAsync(
            "Successful Request",
            "Your new contact needs to accept the request before you can start chatting!");
          break;
        case ResponseCode.NoContactInformationPresent:
          await view.DisplayAlertAsync("Error", "It seems like the provided address is not a valid contact address.");
          break;
        case ResponseCode.MessengerException:
          await view.DisplayAlertAsync("Error", "It seems like the connection to the tangle failed. Try again later or change your node.");
          break;
        default:
          await view.DisplayAlertAsync("Error", "Something seems to be broken. Please try again later.");
          break;
      }
    }
  }
}