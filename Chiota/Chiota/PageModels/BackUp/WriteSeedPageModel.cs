using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using Chiota.Models.BackUp;
using Chiota.PageModels.Classes;
using Chiota.Pages.BackUp;
using Xamarin.Forms;

namespace Chiota.PageModels.BackUp
{
    public class WriteSeedPageModel : BasePageModel
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
            var seed = new Seed(data as string);
            UpdateSeedView(seed);
        }

        #endregion

        #region Methods

        #region UpdateSeedView

        private void UpdateSeedView(Seed seed)
        {
            var tmp = new ObservableCollection<View>();

            foreach (var line in seed.Lines)
            {
                var lineView = new StackLayout
                {
                    Orientation = StackOrientation.Horizontal,
                    Spacing = 4
                };

                foreach (var item in line.Items)
                {
                    //Set the layout for every item.
                    var itemView = new Label
                    {
                        TextColor = Color.FromHex("#ffffff"),
                        HorizontalOptions = LayoutOptions.Center,
                        VerticalOptions = LayoutOptions.Center,
                        FontSize = 14,
                        Text = item
                    };

                    var itemLayout = new Frame
                    {
                        BackgroundColor = (Color)Application.Current.Resources["AccentColor"],
                        HorizontalOptions = LayoutOptions.Center,
                        VerticalOptions = LayoutOptions.Center,
                        Padding = new Thickness(0),
                        HeightRequest = 32,
                        WidthRequest = 32,
                        CornerRadius = 8,
                        Content = itemView
                    };

                    lineView.Children.Add(itemLayout);
                }
                tmp.Add(lineView);
            }

            //Clear the current seed view.
            Seed = null;

            //Set the new one.
            Seed = tmp;
        }

        #endregion

        #endregion

        #region Commands

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                {
                    await PopAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
