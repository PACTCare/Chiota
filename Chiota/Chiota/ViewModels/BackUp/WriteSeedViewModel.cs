namespace Chiota.ViewModels.BackUp
{
  using System.Collections.ObjectModel;
  using System.Windows.Input;

  using Chiota.Models.BackUp;
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The write seed view model.
  /// </summary>
  public class WriteSeedViewModel : BaseViewModel
  {
    private bool isDownVisible;

    private bool isSeedViewVisible;

    private bool isUpVisible;

    private Seed seed;

    private int seedLinePointer;

    private Thickness seedViewPadding;

    private ObservableCollection<View> visibleSeedLines;

    public ICommand ContinueCommand => new Command(async () => { await this.PopAsync(); });

    /// <summary>
    /// Gets the down command.
    /// </summary>
    public ICommand DownCommand
    {
      get
      {
        return new Command(
          () =>
            {
              if (this.seedLinePointer > 8)
              {
                return;
              }

              this.seedLinePointer++;
              this.IsUpVisible = true;

              if (this.seedLinePointer == 8)
              {
                this.IsDownVisible = false;
                this.SeedViewPadding = new Thickness(0, 0, 0, 36);
              }
              else
              {
                this.SeedViewPadding = new Thickness(0);
              }

              this.UpdateSeedView();
            });
      }
    }

    /// <summary>
    /// Gets the up command.
    /// </summary>
    public ICommand UpCommand
    {
      get
      {
        return new Command(
          () =>
            {
              if (this.seedLinePointer < 0)
              {
                return;
              }

              this.seedLinePointer--;
              this.IsDownVisible = true;
              if (this.seedLinePointer == 0)
              {
                this.IsUpVisible = false;
                this.SeedViewPadding = new Thickness(0, 36, 0, 0);
              }
              else
              {
                this.SeedViewPadding = new Thickness(0);
              }

              this.UpdateSeedView();
            });
      }
    }

    /// <summary>
    /// Gets or sets a value indicating whether is down visible.
    /// </summary>
    public bool IsDownVisible
    {
      get => this.isDownVisible;
      set
      {
        this.isDownVisible = value;
        this.OnPropertyChanged(nameof(this.IsDownVisible));
      }
    }

    /// <summary>
    /// Gets or sets a value indicating whether is seed view visible.
    /// </summary>
    public bool IsSeedViewVisible
    {
      get => this.isSeedViewVisible;
      set
      {
        this.isSeedViewVisible = value;
        this.OnPropertyChanged(nameof(this.IsSeedViewVisible));
      }
    }

    /// <summary>
    /// Gets or sets a value indicating whether is up visible.
    /// </summary>
    public bool IsUpVisible
    {
      get => this.isUpVisible;
      set
      {
        this.isUpVisible = value;
        this.OnPropertyChanged(nameof(this.IsUpVisible));
      }
    }

    /// <summary>
    /// Gets or sets the seed view padding.
    /// </summary>
    public Thickness SeedViewPadding
    {
      get => this.seedViewPadding;
      set
      {
        this.seedViewPadding = value;
        this.OnPropertyChanged(nameof(this.SeedViewPadding));
      }
    }

    /// <summary>
    /// Gets or sets the visible seed lines.
    /// </summary>
    public ObservableCollection<View> VisibleSeedLines
    {
      get => this.visibleSeedLines;
      set
      {
        this.visibleSeedLines = value;
        this.OnPropertyChanged(nameof(this.VisibleSeedLines));
      }
    }

    /// <summary>
    /// The init.
    /// </summary>
    /// <param name="data">
    /// The data.
    /// </param>
    public override void Init(object data = null)
    {
      this.SeedViewPadding = new Thickness(0, 36, 0, 0);

      // Reset view.
      this.seedLinePointer = 0;
      this.IsUpVisible = false;
      this.IsDownVisible = true;

      // Set a new generated seed.
      this.seed = new Seed(data as string);
      this.UpdateSeedView();
      this.IsSeedViewVisible = true;

      base.Init(data);
    }

    /// <summary>
    /// The update seed view.
    /// TODO: Remove code duplication (see NewSeedViewModel)
    /// </summary>
    private void UpdateSeedView()
    {
      var enabledPointer = 1;
      if (this.seedLinePointer == 0)
      {
        enabledPointer = 0;
      }
      else if (this.seedLinePointer == 8)
      {
        enabledPointer = 2;
      }

      var visibleIndex = 0;
      if (this.seedLinePointer > 1 && this.seedLinePointer < 6)
      {
        visibleIndex = this.seedLinePointer - 1;
      }
      else if (this.seedLinePointer >= 6)
      {
        visibleIndex = 6;
      }

      var seedLines = this.seed.Lines.GetRange(visibleIndex, 3);
      var tmp = new ObservableCollection<View>();

      for (var i = 0; i < seedLines.Count; i++)
      {
        var lineView = new StackLayout { Orientation = StackOrientation.Horizontal, Spacing = 2 };

        if (i != enabledPointer)
        {
          lineView.IsEnabled = false;
        }

        for (var j = 0; j < seedLines[i].Items.Count; j++)
        {
          var backgroundColor = (Color)Application.Current.Resources["AccentColor"];

          // Set the layout for every item.
          var itemView = new Label
                           {
                             TextColor = Color.FromHex("#ffffff"),
                             HorizontalOptions = LayoutOptions.Center,
                             VerticalOptions = LayoutOptions.Center,
                             FontSize = 10,
                             Margin = new Thickness(0),
                             Text = seedLines[i].Items[j]
                           };

          var itemLayout = new Frame
                             {
                               BackgroundColor = backgroundColor,
                               HorizontalOptions = LayoutOptions.Center,
                               VerticalOptions = LayoutOptions.Center,
                               Padding = new Thickness(0),
                               HeightRequest = 32,
                               WidthRequest = 32,
                               CornerRadius = 8,
                               Content = itemView
                             };

          if (i != enabledPointer)
          {
            itemLayout.BackgroundColor = Color.FromRgba(backgroundColor.R, backgroundColor.G, backgroundColor.B, 0.6);
          }

          lineView.Children.Add(itemLayout);
        }

        tmp.Add(lineView);
      }

      // Set the new one.
      this.VisibleSeedLines = tmp;
    }
  }
}