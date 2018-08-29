using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using Chiota.Models.BackUp;
using Chiota.PageModels.Classes;
using Chiota.Pages.BackUp;
using Xamarin.Forms;

namespace Chiota.PageModels.Authentication
{
    public class NewSeedPageModel : BasePageModel
    {
        #region Attributes

        private ObservableCollection<View> _seed;

        #endregion

        #region Properties

        public ObservableCollection<View> Seed
        {
            get => _seed;
            set
            {
                _seed = value;
                OnPropertyChanged(nameof(Seed));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            //Set a new generated seed.
            var seed = new Seed(GetNewSeed());
            UpdateSeedView(seed);
        }

        #endregion

        #region Methods

        #region GetNewSeed

        private string GetNewSeed()
        {
            //TODO Implementation to generate a new seed.
            return "OXPVBCX9VBLE99HXVHDXOXULQDSQJXDXY9XYQSWWBTVVZWPEIFYIJNCSKQTSLVW9EDPDHSFGHCH9YYVXP";
        }

        #endregion

        #region UpdateSeedView

        private void UpdateSeedView(Seed seed)
        {
            var tmp = new ObservableCollection<View>();

            foreach (var line in seed.Lines)
            {
                var lineView = new StackLayout
                {
                    Orientation = StackOrientation.Horizontal,
                    Spacing = 2
                };

                foreach (var item in line.Items)
                {
                    //Set the layout for every item.
                    var itemView = new Button
                    {
                        TextColor = Color.FromHex("#ffffff"),
                        BackgroundColor = (Color) Application.Current.Resources["AccentColor"],
                        HeightRequest = 32,
                        WidthRequest = 32,
                        HorizontalOptions = LayoutOptions.Center,
                        VerticalOptions = LayoutOptions.Center,
                        CornerRadius = 8,
                        FontSize = 10,
                        Text = item,
                        Command = SeedLetterCommand
                    };
                    itemView.CommandParameter = itemView;
                    lineView.Children.Add(itemView);
                }
                tmp.Add(lineView);
            }

            //Clear the current seed view.
            Seed = null;

            //Set the new one.
            Seed = tmp;
        }

        #endregion

        #region ExtractSeed

        /// <summary>
        /// Extract the seed from the view.
        /// Maybe the user change single characters of the seed,
        /// so we need the actual one.
        /// </summary>
        /// <returns></returns>
        private string ExtractSeed()
        {
            var result = string.Empty;

            foreach (var child in Seed)
            {
                if (!(child is StackLayout layout)) return null;
                foreach (var item in layout.Children)
                {
                    if (!(item is Button button)) return null;
                    result += button.Text.Replace("\0", "");
                }
            }
            return result.Length != 81 ? null : result;
        }

        #endregion

        #endregion

        #region Commands

        #region GenerateSeed

        public ICommand GenerateSeedCommand
        {
            get
            {
                return new Command(() =>
                {
                    var seed = new Seed(GetNewSeed());
                    UpdateSeedView(seed);
                });
            }
        }

        #endregion

        #region SeedLetter

        public ICommand SeedLetterCommand
        {
            get
            {
                return new Command((item) =>
                {
                    if(!(item is Button button)) return;

                    //Get the seed items random by utf8.
                    var random = new Random();
                    var result = random.Next(65, 91);
                    if (result == 91)
                        result = 57;

                    button.Text = Encoding.UTF8.GetString(BitConverter.GetBytes(result));
                });
            }
        }

        #endregion

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                {
                    var seed = ExtractSeed();
                    await PushAsync(new BackUpPage(), seed);
                });
            }
        }

        #endregion

        #endregion
    }
}
