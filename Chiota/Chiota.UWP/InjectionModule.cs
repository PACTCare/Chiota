#region References

using Autofac;
using Chiota.Persistence;
using Chiota.Services;
using Chiota.UWP.Services;
using Pact.Palantir.Cache;
using Pact.Palantir.Repository;

#endregion

namespace Chiota.UWP
{
    /// <inheritdoc />
    public class InjectionModule : Module
    {
        /// <inheritdoc />
        protected override void Load(ContainerBuilder builder)
        {
            builder.RegisterType<TransactionCacheRepository>().As<ITransactionCache>();
            builder.RegisterType<ContactRepository>().As<IContactRepository>().PropertiesAutowired();
        }
    }
}
