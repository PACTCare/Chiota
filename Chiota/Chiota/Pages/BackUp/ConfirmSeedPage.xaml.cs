namespace Chiota.Pages.BackUp
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The confirm seed page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class ConfirmSeedPage : ContentPage
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="ConfirmSeedPage"/> class.
    /// </summary>
    public ConfirmSeedPage()
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