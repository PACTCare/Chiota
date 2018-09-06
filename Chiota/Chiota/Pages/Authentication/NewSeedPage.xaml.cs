namespace Chiota.Pages.Authentication
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The new seed page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class NewSeedPage : ContentPage
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="NewSeedPage"/> class.
    /// </summary>
    public NewSeedPage()
    {
      this.InitializeComponent();

      if (this.BindingContext is BaseViewModel viewmodel)
      {
        viewmodel.Setup(this);
      }
    }
  }
}