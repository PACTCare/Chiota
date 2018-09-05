using System;
using System.Threading.Tasks;
using System.Windows.Input;

using Chiota.Events;
using Chiota.Extensions;
using Chiota.Models;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;
using Chiota.Services;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Iota;
using Chiota.Services.Navigation;
using Chiota.Services.Storage;
using Chiota.Services.UserServices;
using Chiota.Views;

using Tangle.Net.Entity;
using Tangle.Net.Utils;

using Xamarin.Forms;
using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
    public class LoginViewModel : BaseViewModel
    {
        #region Attributes

        private string randomSeed;
        private bool storeSeed;
        private User user;

        private readonly IUserFactory userFactory;

        /// <summary>
        /// Event raised as soon as a user logged in successfully.
        /// Outputs EventArgs of type <see cref="LoginEventArgs"/>
        /// </summary>
        public static event EventHandler LoginSuccessful;

        #endregion

        #region Properties

        public bool StoreSeed
        {
            get => storeSeed;
            set
            {
                storeSeed = value;
                RaisePropertyChanged(nameof(StoreSeed));
            }
        }

        public string RandomSeed
        {
            get => randomSeed ?? string.Empty;
            set
            {
                randomSeed = value;
                RaisePropertyChanged(nameof(RandomSeed));
            }
        }

        #endregion

        #region Constructors

        public LoginViewModel()
        {
            StoreSeed = true;
            randomSeed = Seed.Random().Value;
            userFactory = DependencyResolver.Resolve<IUserFactory>();
        }

        #endregion

        #region Methods

        private async Task LoginAsync()
        {
            //Create alert object.
            //We can optimize this, if we predifine our exception messages in classes
            //and show the alerts by calling a show method of the exceptions. TODO
            var alert = new AlertPopupModel()
            {
                Title = "Error",
                Message = "Invalid seed, try again"
            };

            RandomSeed = RandomSeed.Trim();
            if (!InputValidator.IsTrytes(RandomSeed))
                //Show invalid seed exception.
                await Navigation.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(new AlertPopupPage(), alert);
            else if (!IsBusy)
            {
                await this.DisplayLoadingSpinnerAsync("Addresses are generated...");

                //Create a new user, if no instance exist yet.
                if (UserNotYetGenerated())
                    user = await userFactory.CreateAsync(new Seed(RandomSeed), StoreSeed);

                //Get the public key and contact addresses.
                var publicKeyList = await IotaHelper.GetPublicKeysAndContactAddresses(user.TangleMessenger, user.PublicKeyAddress);

                // PublicKeyList should never be zero if this seed was used before (checks sqlite)
                if (publicKeyList.Count == 0)
                {
                    user.ImageHash = Application.Current.Properties[ChiotaConstants.SettingsImageKey + user.PublicKeyAddress] as string;
                    user.Name = Application.Current.Properties[ChiotaConstants.SettingsNameKey + user.PublicKeyAddress] as string;
                    await PopPopupAsync();
                    await Navigation.PushModalAsync(new NavigationPage(new CheckSeedStoredPage(user)));
                }
                else
                {
                    user = await new UserDataOnTangle(user).UniquePublicKey();
                    new SecureStorage().StoreUser(user);

                    if (user.NtruKeyPair != null)
                    {
                        //Invake the login event.
                        LoginSuccessful?.Invoke(this, new LoginEventArgs { User = user });
                        UserService.SetCurrentUser(user);
                        Application.Current.MainPage = new NavigationPage(DependencyResolver.Resolve<INavigationService>().LoggedInEntryPoint);

                        await PopPopupAsync();
                        //Pop to the root page.
                        await Navigation.PopToRootAsync(true);
                    }
                    else
                    {
                        await PopPopupAsync();
                        //Show invalid seed exception.
                        await Navigation.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(new AlertPopupPage(), alert);
                    }
                }
            }
        }

        /// <summary>
        /// Returns if the user is generated yes.
        /// </summary>
        /// <returns>Boolean, if user generated.</returns>
        private bool UserNotYetGenerated()
        {
            return user == null || RandomSeed != user?.Seed.Value;
        }

        #endregion

        #region Commands

        #region SubmitCommand

        public ICommand SubmitCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await LoginAsync();
                });
            }
        }

        #endregion

        #region CopySeedCommand

        public ICommand CopySeedCommand
        {
            get
            {
                return new Command(async () =>
                {
                    var alert = new AlertPopupModel()
                    {
                        Title = "Copied",
                        Message = "The seed has been copied to your clipboard."
                    };
                    await Navigation.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(new AlertPopupPage(), alert);

                    DependencyResolver.Resolve<IClipboardService>().SendTextToClipboard(RandomSeed);
                });
            }
        }

        #endregion

        #endregion
    }
}