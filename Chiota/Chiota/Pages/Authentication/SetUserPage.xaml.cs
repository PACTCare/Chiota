namespace Chiota.Pages.Authentication
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The set user page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class SetUserPage : ContentPage
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="SetUserPage"/> class.
    /// </summary>
    public SetUserPage()
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