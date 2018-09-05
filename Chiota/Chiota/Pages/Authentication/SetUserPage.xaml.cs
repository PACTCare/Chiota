namespace Chiota.Pages.Authentication
{
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Authentication;
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
      this.BindingContext = new SetUserViewModel(DependencyResolver.Resolve<UserService>());

      ((BaseViewModel)this.BindingContext).Setup(this);
    }
  }
}