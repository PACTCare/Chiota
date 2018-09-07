namespace Chiota.Popups.PopupModels
{
  using Chiota.Popups.Classes;
  using Chiota.Resources.Localizations;

  public class AlertPopupModel : BasePopupModel
  {
    public AlertPopupModel()
    {
      // Set default attributes
      this.PosButtonText = AppResources.DlgOk;
      this.NegButtonText = AppResources.DlgCancel;
    }

    public bool IsNegButtonDefault { get; set; }

    public bool IsNegButtonVisible { get; set; }

    public bool IsTitleVisible { get; set; }

    public string Message { get; set; }

    public string NegButtonText { get; set; }

    public string PosButtonText { get; set; }

    public bool Result { get; set; }

    public string Title { get; set; }
  }
}