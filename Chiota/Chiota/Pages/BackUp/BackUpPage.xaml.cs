namespace Chiota.Pages.BackUp
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The back up page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class BackUpPage : ContentPage
  {
    /// <summary>
    /// Initializes a new instance of the <see cref="BackUpPage"/> class.
    /// </summary>
    public BackUpPage()
    {
      this.InitializeComponent();

      if (this.BindingContext is BaseViewModel viewmodel)
      {
        viewmodel.Setup(this);
      }
    }
  }
}