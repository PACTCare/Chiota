namespace Chiota.Messenger.Cucumber.Drivers
{
  using System.Collections.Generic;
  using System.Linq;

  using Chiota.Messenger.Cucumber.Models;
  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Messenger.Usecase.CreateUser;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.Messenger.Usecase.SendMessage;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  public class UserDriver
  {
    public UserDriver()
    {
      this.Users = new List<User>();
    }

    public List<User> Users { get; set; }

    public CreateUserResponse CreateUser(string username)
    {
      var seed = Seed.Random();
      var response = InstanceBag.CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = seed }).Result;

      if (response.Code == ResponseCode.Success)
      {
        this.Users.Add(
          new User
            {
              Seed = seed,
              NtruKeyPair = response.NtruKeyPair,
              PublicKeyAddress = response.PublicKeyAddress,
              RequestAddress = response.RequestAddress,
              Name = username,
              ChatKeyPair = null
            });
      }

      return response;
    }

    public AddContactResponse RequestContact(string senderName, string receiverName)
    {
      var sender = this.Users.First(u => u.Name == senderName);
      var receiver = this.Users.First(u => u.Name == receiverName);

      var response = InstanceBag.AddContactInteractor.ExecuteAsync(
        new AddContactRequest
          {
            Name = sender.Name,
            ImageHash = string.Empty,
            RequestAddress = sender.RequestAddress,
            PublicKeyAddress = sender.PublicKeyAddress,
            ContactAddress = receiver.PublicKeyAddress
          }).Result;

      if (response.Code == ResponseCode.Success)
      {
        sender.Contacts.Add(
          new Contact
            {
              IsApproved = false,
              Name = receiver.Name,
              NtruKeyPair = receiver.NtruKeyPair,
              PublicKeyAddress = receiver.PublicKeyAddress,
              RequestAddress = receiver.RequestAddress,
              Seed = receiver.Seed
            });
      }

      return response;
    }

    public AcceptContactResponse AcceptContact(string receiverName, string senderName)
    {
      var sender = this.Users.First(u => u.Name == senderName);
      var receiver = this.Users.First(u => u.Name == receiverName);

      var contactResponse = InstanceBag.GetContactsInteractor.ExecuteAsync(
        new GetContactsRequest { ContactRequestAddress = receiver.RequestAddress, PublicKeyAddress = receiver.PublicKeyAddress }).Result;
      if (contactResponse.Code != ResponseCode.Success)
      {
        Assert.Fail($"Can not get contacts. {contactResponse.Code}");
      }

      var contact = contactResponse.PendingContactRequests.FirstOrDefault(c => c.Name == senderName);
      if (contact == null)
      {
        Assert.Fail($"Given contact ({senderName}) does not exist as pending contact!");
      }

      var acceptResponse = InstanceBag.AcceptContactInteractor.ExecuteAsync(
        new AcceptContactRequest
          {
            UserName = receiver.Name,
            UserImageHash = string.Empty,
            ChatAddress = new Address(contact.ChatAddress),
            ChatKeyAddress = new Address(contact.ChatKeyAddress),
            ContactAddress = new Address(contact.ContactAddress),
            ContactPublicKeyAddress = new Address(contact.PublicKeyAddress),
            UserPublicKeyAddress = receiver.PublicKeyAddress,
            UserKeyPair = receiver.NtruKeyPair
          }).Result;

      if (acceptResponse.Code == ResponseCode.Success)
      {
        receiver.Contacts.Add(
          new Contact
            {
              IsApproved = true,
              Name = sender.Name,
              NtruKeyPair = sender.NtruKeyPair,
              PublicKeyAddress = sender.PublicKeyAddress,
              RequestAddress = sender.RequestAddress,
              Seed = sender.Seed,
              ChatAddress = new Address(contact.ChatAddress),
              ChatKeyAddress = new Address(contact.ChatKeyAddress)
          });

        sender.Contacts.First(c => c.Name == receiver.Name).IsApproved = true;
        sender.Contacts.First(c => c.Name == receiver.Name).ChatAddress = new Address(contact.ChatAddress);
        sender.Contacts.First(c => c.Name == receiver.Name).ChatKeyAddress = new Address(contact.ChatKeyAddress);
      }

      return acceptResponse;
    }

    public SendMessageResponse SendMessage(string senderName, string message, string receiverName)
    {
      var sender = this.Users.First(u => u.Name == senderName);
      var receiver = this.Users.First(u => u.Name == receiverName);

      if (sender.Contacts.First(c => c.Name == receiver.Name).ChatKeyPair == null)
      {
        this.GetMessages(senderName, receiverName);
      }

      var response = InstanceBag.SendMessageInteractor.ExecuteAsync(
        new SendMessageRequest
          {
            Message = message,
            UserPublicKeyAddress = sender.PublicKeyAddress,
            KeyPair = sender.Contacts.First(c => c.Name == receiver.Name).ChatKeyPair,
            ChatAddress = sender.Contacts.First(c => c.Name == receiver.Name).ChatAddress
          }).Result;

      return response;
    }

    public GetMessagesResponse GetMessages(string receiverName, string senderName)
    {
      var sender = this.Users.First(u => u.Name == senderName);
      var receiver = this.Users.First(u => u.Name == receiverName);

      var response = InstanceBag.GetMessagesInteractor.ExecuteAsync(
        new GetMessagesRequest
          {
            ChatAddress = receiver.Contacts.First(c => c.Name == sender.Name).ChatAddress,
            ChatKeyPair = receiver.Contacts.First(c => c.Name == sender.Name).ChatKeyPair,
            ChatKeyAddress = receiver.Contacts.First(c => c.Name == sender.Name).ChatKeyAddress,
            UserKeyPair = receiver.NtruKeyPair
          }).Result;

      // ReSharper disable once InvertIf
      if (response.Code == ResponseCode.Success)
      {
        receiver.Contacts.First(c => c.Name == sender.Name).ChatKeyPair = response.ChatKeyPair;
        receiver.Contacts.First(c => c.Name == sender.Name).ChatAddress = response.CurrentChatAddress;

        sender.Contacts.First(c => c.Name == receiver.Name).ChatKeyPair = response.ChatKeyPair;
        sender.Contacts.First(c => c.Name == receiver.Name).ChatAddress = response.CurrentChatAddress;
      }

      return response;
    }
  }
}