namespace Chiota.ViewModels.Authentication
{
  using System;
  using System.Collections.ObjectModel;
  using System.Text;
  using System.Windows.Input;

  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.Models.BackUp;
  using Chiota.Pages.BackUp;
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The new seed view model.
  /// </summary>
  public class NewSeedViewModel : BaseViewModel
  {
    /// <summary>
    /// The _is down visible.
    /// </summary>
    private bool _isDownVisible;

    /// <summary>
    /// The _is seed view visible.
    /// </summary>
    private bool _isSeedViewVisible;

    /// <summary>
    /// The _is up visible.
    /// </summary>
    private bool _isUpVisible;

    /// <summary>
    /// The _seed.
    /// </summary>
    private Seed _seed;

    /// <summary>
    /// The _seed line pointer.
    /// </summary>
    private int _seedLinePointer;

    /// <summary>
    /// The _seed view padding.
    /// </summary>
    private Thickness _seedViewPadding;

    /// <summary>
    /// The _visible seed lines.
    /// </summary>
    private ObservableCollection<View> _visibleSeedLines;

    /// <summary>
    /// Gets the continue command.
    /// </summary>
    public ICommand ContinueCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              // If there exist no seed, show missing seed exception.
              if (this._seed == null)
              {
                await new AuthMissingSeedException(new ExcInfo()).ShowAlertAsync();
                return;
              }

              var seed = this.ExtractSeed();
              await this.PushAsync(new BackUpPage(), seed);
            });
      }
    }

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
              if (this._seedLinePointer > 8)
              {
                return;
              }

              this._seedLinePointer++;
              this.IsUpVisible = true;
              if (this._seedLinePointer == 8)
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
    /// Gets the generate seed command.
    /// </summary>
    public ICommand GenerateSeedCommand
    {
      get
      {
        return new Command(
          () =>
            {
              this._seed = new Seed(this.GetNewSeed());

              // Reset view.
              this._seedLinePointer = 0;
              this.IsUpVisible = false;
              this.IsDownVisible = true;

              this.UpdateSeedView();

              // Show seed view.
              this.IsSeedViewVisible = true;
            });
      }
    }

    /// <summary>
    /// Gets or sets a value indicating whether is down visible.
    /// </summary>
    public bool IsDownVisible
    {
      get => this._isDownVisible;
      set
      {
        this._isDownVisible = value;
        this.OnPropertyChanged(nameof(this.IsDownVisible));
      }
    }

    /// <summary>
    /// Gets or sets a value indicating whether is seed view visible.
    /// </summary>
    public bool IsSeedViewVisible
    {
      get => this._isSeedViewVisible;
      set
      {
        this._isSeedViewVisible = value;
        this.OnPropertyChanged(nameof(this.IsSeedViewVisible));
      }
    }

    /// <summary>
    /// Gets or sets a value indicating whether is up visible.
    /// </summary>
    public bool IsUpVisible
    {
      get => this._isUpVisible;
      set
      {
        this._isUpVisible = value;
        this.OnPropertyChanged(nameof(this.IsUpVisible));
      }
    }

    /// <summary>
    /// Gets the seed letter command.
    /// </summary>
    public ICommand SeedLetterCommand
    {
      get
      {
        return new Command(
          (array) =>
            {
              var items = array as object[];
              var pointer = (int)items[0];
              var item = items[1] as Button;

              if (!(item is Button button)) return;

              // Get the seed items random by utf8.
              var random = new Random();
              var result = random.Next(65, 91);
              if (result == 91)
                result = 57;

              // Update the seed attribute.
              var resultChar = Encoding.UTF8.GetString(BitConverter.GetBytes(result)).Replace("\0", string.Empty);
              this._seed.Lines[this._seedLinePointer].Items[pointer] = resultChar;
              button.Text = resultChar;
            });
      }
    }

    /// <summary>
    /// Gets or sets the seed view padding.
    /// </summary>
    public Thickness SeedViewPadding
    {
      get => this._seedViewPadding;
      set
      {
        this._seedViewPadding = value;
        this.OnPropertyChanged(nameof(this.SeedViewPadding));
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
              if (this._seedLinePointer >= 0)
              {
                this._seedLinePointer--;
                this.IsDownVisible = true;
                if (this._seedLinePointer == 0)
                {
                  this.IsUpVisible = false;
                  this.SeedViewPadding = new Thickness(0, 36, 0, 0);
                }
                else this.SeedViewPadding = new Thickness(0);

                this.UpdateSeedView();
              }
            });
      }
    }

    /// <summary>
    /// Gets or sets the visible seed lines.
    /// </summary>
    public ObservableCollection<View> VisibleSeedLines
    {
      get => this._visibleSeedLines;
      set
      {
        this._visibleSeedLines = value;
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

      base.Init(data);
    }

    /// <summary>
    /// Extract the seed from the view.
    /// Maybe the user change single characters of the seed,
    /// so we need the actual one.
    /// </summary>
    /// <returns>
    /// The <see cref="string"/>.
    /// </returns>
    private string ExtractSeed()
    {
      var result = string.Empty;

      foreach (var line in this._seed.Lines)
      {
        foreach (var item in line.Items)
        {
          result += item;
        }
      }

      return result.Length != 81 ? null : result;
    }

    /// <summary>
    /// Returns a new generated iota seed.
    /// </summary>
    /// <returns>
    /// The <see cref="string"/>.
    /// </returns>
    private string GetNewSeed()
    {
      return Tangle.Net.Entity.Seed.Random().Value;
    }

    /// <summary>
    /// The update seed view.
    /// </summary>
    private void UpdateSeedView()
    {
      // Set the pointer for different layouts for the view.
      var enabledPointer = 1;
      if (this._seedLinePointer == 0)
        enabledPointer = 0;
      else if (this._seedLinePointer == 8)
        enabledPointer = 2;

      var visibleIndex = 0;
      if (this._seedLinePointer > 1 && this._seedLinePointer < 6)
        visibleIndex = this._seedLinePointer - 1;
      else if (this._seedLinePointer >= 6)
        visibleIndex = 6;

      var seedLines = this._seed.Lines.GetRange(visibleIndex, 3);
      var tmp = new ObservableCollection<View>();

      for (var i = 0; i < seedLines.Count; i++)
      {
        var lineView = new StackLayout { Orientation = StackOrientation.Horizontal, Spacing = 2 };

        if (i != enabledPointer)
          lineView.IsEnabled = false;

        for (var j = 0; j < seedLines[i].Items.Count; j++)
        {
          var backgroundColor = (Color)Application.Current.Resources["AccentColor"];

          // Set the layout for every item.
          var itemView = new Button
                           {
                             TextColor = Color.FromHex("#ffffff"),
                             BackgroundColor = backgroundColor,
                             HeightRequest = 32,
                             WidthRequest = 32,
                             HorizontalOptions = LayoutOptions.Center,
                             VerticalOptions = LayoutOptions.Center,
                             CornerRadius = 8,
                             FontSize = 10,
                             Text = seedLines[i].Items[j],
                             Command = this.SeedLetterCommand,
                           };
          itemView.CommandParameter = new object[] { j, itemView };

          if (i != enabledPointer)
            itemView.BackgroundColor = Color.FromRgba(backgroundColor.R, backgroundColor.G, backgroundColor.B, 0.6);

          lineView.Children.Add(itemView);
        }

        tmp.Add(lineView);
      }

      // Set the new one.
      this.VisibleSeedLines = tmp;
    }
  }
}