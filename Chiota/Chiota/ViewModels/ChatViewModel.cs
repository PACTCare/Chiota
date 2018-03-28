namespace Chiota.ViewModels
{
  using System;
  using System.Collections.Generic;
  using System.Collections.ObjectModel;
  using System.Globalization;
  using System.Linq;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  public class ChatViewModel : BaseViewModel
  {
    public Action DisplayMessageTooLong;

    private readonly string profileImageUrl;

    private readonly User user;

    private readonly Contact contact;

    private readonly NtruKex ntruKex;

    private int postedCount;

    private string outgoingText;

    private ObservableCollection<MessageViewModel> messagesList;

    public ChatViewModel(Contact contact, User user)
    {
      this.ntruKex = new NtruKex();

      this.profileImageUrl = contact.ImageUrl;
      this.user = user;
      this.contact = contact;

      var trytes = this.user.TangleMessenger.GetMessages(this.contact.PublicKeyAdress);
      var contactInfos = IotaHelper.FilterRequestInfos(trytes);
      contact.PublicNtruKey = contactInfos.PublicNtruKey;

      this.Messages = new ObservableCollection<MessageViewModel>();

      this.GetMessagesAsync(this.Messages);

      this.OutGoingText = null;
      this.SendCommand = new Command(async () => { await this.SendMessage(); });
    }

    public string OutGoingText
    {
      get => this.outgoingText;
      set
      {
        this.outgoingText = value;
        this.RaisePropertyChanged();
      }
    }

    public ICommand SendCommand { get; set; }

    public ObservableCollection<MessageViewModel> Messages
    {
      get => this.messagesList;
      set
      {
        this.messagesList = value;
        this.RaisePropertyChanged();
      }
    }

    private async Task SendMessage()
    {
      this.IsBusy = true;

      // No json object, because of the 106 character limit
      if (this.OutGoingText.Length > 106)
      {
        this.DisplayMessageTooLong();
      }
      else
      {
        var trytesDate = TryteString.FromUtf8String(DateTime.UtcNow.ToString(CultureInfo.InvariantCulture));

        // encryption with public key of other user
        var encryptedMessage = this.ntruKex.Encrypt(this.contact.PublicNtruKey, this.OutGoingText);
        await this.user.TangleMessenger.SendMessage(new TryteString(encryptedMessage.ToTrytes() + "9CHIOTAYOURIOTACHATAPP9" + trytesDate + "9ENDEGUTALLESGUT9"), this.contact.ChatAdress);

        // needs to store own messages somehow, can not be decrypted later
        this.Messages.Add(new MessageViewModel { Text = this.OutGoingText, IsIncoming = false, ProfileImage = this.profileImageUrl, MessagDateTime = DateTime.UtcNow });
      }

      this.IsBusy = false;
      this.OutGoingText = null;
    }

    private async void GetMessagesAsync(ICollection<MessageViewModel> messages)
    {
      while (true)
      {
        this.AddNewMessages(messages);
        await Task.Delay(8000);
      }
    }

    private void AddNewMessages(ICollection<MessageViewModel> messages)
    {
      var decryptedMessages = this.user.TangleMessenger.GetMessages(this.contact.ChatAdress);
      var messageList = IotaHelper.FilterChatMessages(decryptedMessages, this.ntruKex, this.user.NtruKeyPair);
      if (messageList != null)
      {
        var sortedMessageList = messageList.OrderBy(o => o.Date).ToList();
        for (var i = 0; i < sortedMessageList.Count && i >= this.postedCount; i++)
        {
          messages.Add(
            new MessageViewModel
            {
              Text = sortedMessageList[i].Message,
              IsIncoming = true,
              MessagDateTime = sortedMessageList[i].Date,
              ProfileImage = this.profileImageUrl
            });
          this.postedCount++;
        }
      }
    }
  }
}