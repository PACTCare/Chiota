using Chiota.ViewModels.Classes;

namespace Chiota.Views.Authentication
{
    using Xamarin.Forms;
    using Xamarin.Forms.Xaml;

    /// <inheritdoc />
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class SetUserView : ContentPage
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SetUserView"/> class.
        /// </summary>
        public SetUserView()
        {
            InitializeComponent();

            if (BindingContext is BaseViewModel viewModel)
                viewModel.Setup(this);
        }
    }
}