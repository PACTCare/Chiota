namespace Chiota.Services.DependencyInjection
{
  using System;
  using System.Collections.Generic;

  using Autofac;
  using Autofac.Core;

  using Chiota.Services.Iota;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Pact.Palantir.Encryption;
  using Pact.Palantir.Service;
  using Pact.Palantir.Usecase;
  using Pact.Palantir.Usecase.AcceptContact;
  using Pact.Palantir.Usecase.AddContact;
  using Pact.Palantir.Usecase.CheckUser;
  using Pact.Palantir.Usecase.CreateUser;
  using Pact.Palantir.Usecase.DeclineContact;
  using Pact.Palantir.Usecase.GetContacts;
  using Pact.Palantir.Usecase.GetMessages;
  using Pact.Palantir.Usecase.SendMessage;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.Repository;

  public static class DependencyResolver
  {
    static DependencyResolver()
    {
      Modules = new List<IModule>();
    }

    public static List<IModule> Modules { get; set; }

    private static IContainer Container { get; set; }

    public static void Init()
    {
      var builder = new ContainerBuilder();

      builder.RegisterModule(new ViewModelInjectionModule());
      foreach (var module in Modules)
      {
        builder.RegisterModule(module);
      }

      builder.RegisterType<UserFactory>().As<IUserFactory>();
      builder.RegisterType<UserService>().PropertiesAutowired();
      builder.RegisterInstance(new RepositoryFactory().Create()).As<IIotaRepository>();
      builder.RegisterType<AddressGenerator>().As<IAddressGenerator>();
      builder.RegisterInstance(new SignatureFragmentGenerator(new Kerl())).As<ISignatureFragmentGenerator>();
      builder.RegisterType<SignatureValidator>().As<ISignatureValidator>();

      builder.RegisterType<TangleMessenger>().As<IMessenger>().PropertiesAutowired();

      builder.RegisterType<AddContactInteractor>().As<IUsecaseInteractor<AddContactRequest, AddContactResponse>>().PropertiesAutowired();

      builder.RegisterType<GetContactsInteractor>().As<IUsecaseInteractor<GetContactsRequest, GetContactsResponse>>()
        .WithParameter("encryption", NtruEncryption.Key).PropertiesAutowired();

      builder.RegisterType<AcceptContactInteractor>().As<IUsecaseInteractor<AcceptContactRequest, AcceptContactResponse>>()
        .WithParameter("encryption", NtruEncryption.Key).PropertiesAutowired();

      builder.RegisterType<DeclineContactInteractor>().As<IUsecaseInteractor<DeclineContactRequest, DeclineContactResponse>>().PropertiesAutowired();

      builder.RegisterType<SendMessageInteractor>().As<IUsecaseInteractor<SendMessageRequest, SendMessageResponse>>()
        .WithParameter("messageEncryption", NtruEncryption.Default).WithParameter("keyEncryption", NtruEncryption.Key).PropertiesAutowired();

      builder.RegisterType<CreateUserInteractor>().As<IUsecaseInteractor<CreateUserRequest, CreateUserResponse>>()
        .WithParameter("encryption", NtruEncryption.Key).PropertiesAutowired();

      builder.RegisterType<CheckUserInteractor>().As<IUsecaseInteractor<CheckUserRequest, CheckUserResponse>>().PropertiesAutowired();

      builder.RegisterType<GetMessagesInteractor>().As<IUsecaseInteractor<GetMessagesRequest, GetMessagesResponse>>()
        .WithParameter("messageEncryption", NtruEncryption.Default).WithParameter("keyEncryption", NtruEncryption.Key).PropertiesAutowired();

      builder.RegisterType<UserService>().As<UserService>().PropertiesAutowired();
      Container = builder.Build();
    }

    public static T Resolve<T>()
    {
      if (Container == null)
      {
        Init();
      }

      return Container.Resolve<T>();
    }

    public static object Resolve(Type type)
    {
      if (Container == null)
      {
        Init();
      }

      return Container.Resolve(type);
    }

    public static void Reload()
    {
      Init();
    }
  }
}