namespace Chiota.Presenters
{
  using System.Threading.Tasks;

  using Chiota.Extensions;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;

  using Xamarin.Forms;

  /// <summary>
  /// The add contact presenter.
  /// </summary>
  public class AddContactPresenter
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="AddContactPresenter"/> class.
    /// </summary>
    /// <param name="navigation">
    /// The navigation.
    /// </param>
    public AddContactPresenter(INavigation navigation)
    {
      this.Navigation = navigation;
    }

    /// <summary>
    /// Gets the navigation.
    /// </summary>
    private INavigation Navigation { get; }

    /// <summary>
    /// The present.
    /// </summary>
    /// <param name="response">
    /// The response.
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public async Task Present(AddContactResponse response)
    {
      switch (response.Code)
      {
        case ResponseCode.Success:
          await this.Navigation.DisplayAlertAsync(
            "Successful Request",
            "Your new contact needs to accept the request before you can start chatting!.");
          break;
        case ResponseCode.NoContactInformationPresent:
        case ResponseCode.AmbiguousContactInformation:
          await this.Navigation.DisplayAlertAsync("Error", "It seems like the provided address is not a valid contact address.");
          break;
        case ResponseCode.MessengerException:
          await this.Navigation.DisplayAlertAsync("Error", "It seems like the connection to the tangle failed. Try again later or change your node.");
          break;
        default:
          await this.Navigation.DisplayAlertAsync("Error", "Something seems to be broken. Please try again later.");
          break;
      }
    }
  }
}