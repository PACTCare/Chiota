namespace Chiota.Popups.PopupPageModels
{
  using System.Windows.Input;

  using Chiota.Popups.Classes;
  using Chiota.Popups.PopupModels;

  using Xamarin.Forms;

  /// <summary>
  /// The alert popup page model.
  /// </summary>
  public class AlertPopupPageModel : BasePopupPageModel<AlertPopupModel>
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="AlertPopupPageModel"/> class.
    /// </summary>
    public AlertPopupPageModel()
      : base()
    {
    }

    public AlertPopupPageModel(AlertPopupModel popupModel)
      : base(popupModel)
    {
      if (!string.IsNullOrEmpty(this.PopupModel.Title))
      {
        this.PopupModel.IsTitleVisible = true;
      }

      if (this.PopupModel.IsNegButtonDefault)
      {
        this.NegButtonTextColor = (Color)Application.Current.Resources["HighlightedTextColor"];
        this.PosButtonTextColor = (Color)Application.Current.Resources["FadedTextColor"];
        return;
      }

      this.NegButtonTextColor = (Color)Application.Current.Resources["FadedTextColor"];
      this.PosButtonTextColor = (Color)Application.Current.Resources["HighlightedTextColor"];
    }

    /// <summary>
    /// Gets or sets the neg button text color.
    /// </summary>
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

              this.Finish = true;
              await this.PopPopupAsync();
            });
      }
    }
  }
}