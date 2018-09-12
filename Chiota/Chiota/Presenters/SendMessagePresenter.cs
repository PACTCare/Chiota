namespace Chiota.Presenters
{
  using System.Threading.Tasks;

  using Chiota.Messenger;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.SendMessage;
  using Chiota.ViewModels.Classes;

  /// <summary>
  /// The send message presenter.
  /// </summary>
  public static class SendMessagePresenter
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
    public static async Task Present(BaseViewModel view, SendMessageResponse response)
    {
      switch (response.Code)
      {
        case ResponseCode.Success:
          break;
        case ResponseCode.MessageTooLong:
          await view.DisplayAlertAsync("Error", $"Message is too long. Limit is {Constants.MessageCharacterLimit} characters.");
          break;
        default:
          await view.DisplayAlertAsync("Error", $"Your message couldn't be send. (Code: {(int)response.Code})");
          break;
      }
    }
  }
}