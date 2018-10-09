using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models.Database;
using Microsoft.EntityFrameworkCore;

namespace Chiota.Services.Database.Base
{
    public sealed class DatabaseContext : DbContext
    {
        #region Attributes

        private readonly string _databasePath;

        #endregion

        #region Properties

        public DbSet<DbUser> Users { get; set; }
        public DbSet<DbContact> Contacts { get; set; }
        public DbSet<DbMessage> Messages { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructor of database context
        /// </summary>
        /// <param name="databasePath">Filepath of the database</param>
        public DatabaseContext(string databasePath)
        {
            _databasePath = databasePath;

            // Create database file
            //Database.Migrate();

            Database.EnsureCreated();

            this.ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
        }

        #endregion

        #region Methods

        #region OnConfiguring

        /// <summary>
        /// Configure filepath of database
        /// </summary>
        /// <param name="optionsBuilder">OptionsBuilder of database context</param>
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite($"Filename={_databasePath}");
        }

        #endregion

        #region OnModelCreating

        /// <summary>
        /// 
        /// </summary>
        /// <param name="modelBuilder"></param>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }

        #endregion

        #endregion
    }
}
