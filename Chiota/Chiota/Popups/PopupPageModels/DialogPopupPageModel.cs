namespace Chiota.Popups.PopupPageModels
{
  using System.Windows.Input;

  using Chiota.Popups.Classes;
  using Chiota.Popups.PopupModels;

  using Xamarin.Forms;

  public class DialogPopupPageModel : BasePopupPageModel<DialogPopupModel>
  {
    public DialogPopupPageModel()
      : base()
    {
    }

    public DialogPopupPageModel(DialogPopupModel popupModel)
      : base(popupModel)
    {
      if (this.PopupModel.IsNegButtonDefault)
      {
        this.NegButtonTextColor = (Color)Application.Current.Resources["HighlightedTextColor"];
        this.PosButtonTextColor = (Color)Application.Current.Resources["FadedTextColor"];
        return;
      }

      this.NegButtonTextColor = (Color)Application.Current.Resources["FadedTextColor"];
      this.PosButtonTextColor = (Color)Application.Current.Resources["HighlightedTextColor"];
    }

    public Color NegButtonTextColor { get; set; }

    /// <summary>
    /// Cancel method of the popup
    /// </summary>
    public ICommand NegCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              this.PopupModel.Result = false;
              this.PopupModel.ResultText = string.Empty;

              this.Finish = true;
              await this.PopPopupAsync();
            });
      }
    }

    public Color PosButtonTextColor { get; set; }

    /// <summary>
    /// Ok method of the popup.
    /// </summary>
    public ICommand PosCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              this.PopupModel.Result = true;
              await this.PopPopupAsync();

              if (this.PopupModel.OkCallback != null)
              {
                await this.PopupModel.OkCallback(this.PopupModel.ResultText);
              }

              this.Finish = true;
            });
      }
    }
  }
}