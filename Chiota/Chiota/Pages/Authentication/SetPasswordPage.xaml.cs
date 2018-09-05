namespace Chiota.Pages.Authentication
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The set password page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class SetPasswordPage : ContentPage
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="SetPasswordPage"/> class.
    /// </summary>
    public SetPasswordPage()
    {
      this.InitializeComponent();

      // Setup the pagemodel
      if (this.BindingContext is BaseViewModel viewmodel)
      {
        viewmodel.Setup(this);
      }
    }
  }
}