namespace Chiota.Pages.BackUp
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The write seed page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class WriteSeedPage : ContentPage
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="WriteSeedPage"/> class.
    /// </summary>
    public WriteSeedPage()
    {
      this.InitializeComponent();

      if (this.BindingContext is BaseViewModel viewmodel)
      {
        viewmodel.Setup(this);
      }
    }
  }
}