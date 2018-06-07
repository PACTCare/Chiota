namespace Chiota.Services.DependencyInjection
{
  using System.Collections.Generic;

  using Autofac;
  using Autofac.Core;

  using Chiota.Services.AvatarStorage;
  using Chiota.Services.UserServices;

  /// <summary>
  /// The dependency resolver.
  /// </summary>
  public static class DependencyResolver
  {
    /// <summary>
    /// Initializes static members of the <see cref="DependencyResolver"/> class.
    /// </summary>
    static DependencyResolver()
    {
      Modules = new List<IModule>();
    }

    /// <summary>
    /// Gets or sets the modules.
    /// </summary>
    public static List<IModule> Modules { get; set; }

    /// <summary>
    /// Gets or sets the container.
    /// </summary>
    private static IContainer Container { get; set; }

    /// <summary>
    /// The init.
    /// </summary>
    public static void Init()
    {
      var containerBuilder = new ContainerBuilder();

      containerBuilder.RegisterType<UserFactory>().As<IUserFactory>();
      containerBuilder.RegisterType<BlobStorage>().As<IAvatarStorage>();

      foreach (var module in Modules)
      {
        containerBuilder.RegisterModule(module);
      }

      Container = containerBuilder.Build();
    }

    /// <summary>
    /// The resolve.
    /// </summary>
    /// <typeparam name="T">
    /// The type.
    /// </typeparam>
    /// <returns>
    /// The <see cref="T"/>.
    /// </returns>
    public static T Resolve<T>()
    {
      return Container.Resolve<T>();
    }
  }
}