namespace Chiota.Views.Help
{
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  [XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class SeedHelpView : ContentPage
	{
		public SeedHelpView ()
		{
			this.InitializeComponent ();

		    //Setup the pagemodel
		    if (this.BindingContext is BaseViewModel viewmodel)
		        viewmodel.Setup(this);
        }
	}
}